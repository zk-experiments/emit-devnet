//! Arkworks Groth16 with the upstream Libsnark reduction. The sparse R1CS is
//! generated once natively; proving streams its rows instead of storing matrices.
use anyhow::{Context, Result, ensure};
use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{AdditiveGroup, FftField, Field, PrimeField, UniformRand};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey, prepare_verifying_key};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::gr1cs::{ConstraintSystem, OptimizationGoal, SynthesisMode};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

use crate::fixture::LoadedFixture;

const MAGIC: &[u8; 8] = b"PG16R1C1";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Stats {
    pub constraints: usize,
    pub witnesses: usize,
    pub public_inputs: usize,
    pub circuit_bytes: usize,
    pub prover_key_bytes: u64,
    pub verifier_key_bytes: u64,
    pub matrix_plan_bytes: u64,
    pub domain_size: usize,
    pub decoded_query_bytes: u64,
    pub wasm32_lower_bound_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub backend: String,
    pub noir_version: String,
    pub pipeline: String,
    pub relation_id: String,
    pub setup: String,
    pub stats: Stats,
    pub files: std::collections::BTreeMap<String, String>,
    pub sha256: std::collections::BTreeMap<String, String>,
}

impl Manifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == 1 && self.backend == "arkworks-groth16-bn254" && self.noir_version == "1.0.0-rc.5", "unsupported key manifest");
        ensure!(self.files.len() == 3 && self.sha256.len() == 3, "artifact manifest must contain exactly PK, VK and R1CS");
        for (name, filename) in [("pk", "pk.bin"), ("vk", "vk.bin"), ("r1cs", "r1cs.bin")] {
            ensure!(self.files.get(name).map(String::as_str) == Some(filename), "missing or invalid artifact filename: {name}");
            let hash = self.sha256.get(name).context("missing artifact SHA-256")?;
            ensure!(hash.len() == 64 && hex::decode(hash)?.len() == 32, "invalid artifact SHA-256");
        }
        let degree = self.stats.constraints.checked_add(self.stats.public_inputs).and_then(|n| n.checked_add(1)).context("QAP degree overflow")?;
        ensure!(GeneralEvaluationDomain::<Fr>::new(degree).map(|d| d.size()) == Some(self.stats.domain_size), "invalid QAP domain");
        Ok(())
    }
}

pub struct Session {
    pub fixture: LoadedFixture,
    pub manifest: Manifest,
    pk: ProvingKey<Bn254>,
    pvk: PreparedVerifyingKey<Bn254>,
}

pub fn decode<T: CanonicalDeserialize>(mut input: impl Read) -> Result<T> {
    let value = T::deserialize_compressed(&mut input)?;
    let mut trailing = [0];
    ensure!(input.read(&mut trailing)? == 0, "trailing canonical bytes");
    Ok(value)
}

pub fn encode(value: &impl CanonicalSerialize) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(value.compressed_size());
    value.serialize_compressed(&mut bytes)?;
    Ok(bytes)
}

fn u32_read(input: &mut impl Read) -> Result<usize> {
    let mut bytes = [0; 4];
    input.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes) as usize)
}

fn u32_write(output: &mut impl Write, value: usize) -> Result<()> {
    output.write_all(&u32::try_from(value)?.to_le_bytes())?;
    Ok(())
}

/// Used only by native preparation, with finalized matrices.
pub fn write_plan(output: &mut impl Write, matrices: &[ark_relations::gr1cs::Matrix<Fr>], stats: &Stats) -> Result<()> {
    ensure!(matrices.len() == 3, "expected R1CS A/B/C");
    output.write_all(MAGIC)?;
    u32_write(output, stats.public_inputs + 1)?;
    u32_write(output, stats.witnesses)?;
    u32_write(output, stats.constraints)?;
    for matrix in matrices {
        ensure!(matrix.len() == stats.constraints, "matrix row count mismatch");
        for row in matrix {
            u32_write(output, row.len())?;
            for (coefficient, index) in row {
                u32_write(output, *index)?;
                if *coefficient == Fr::ONE {
                    output.write_all(&[0])?;
                } else if *coefficient == -Fr::ONE {
                    output.write_all(&[1])?;
                } else {
                    output.write_all(&[2])?;
                    coefficient.serialize_compressed(&mut *output)?;
                }
            }
        }
    }
    Ok(())
}

struct Assignment {
    instance: Vec<Fr>,
    witness: Vec<Fr>,
}

impl Assignment {
    fn value(&self, index: usize) -> Result<Fr> {
        if index < self.instance.len() {
            Ok(self.instance[index])
        } else {
            self.witness.get(index - self.instance.len()).copied().context("R1CS variable out of bounds")
        }
    }
}

fn assignments(fixture: &LoadedFixture, stats: &Stats) -> Result<Assignment> {
    // No constraints/matrices or is_satisfied() in device timing. Arkworks still
    // retains evaluated symbolic LCs until this CS is dropped after synthesis.
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove { construct_matrices: false, generate_lc_assignments: true });
    fixture.generate_witness_constraints(cs.clone())?;
    ensure!(cs.num_instance_variables() == stats.public_inputs + 1 && cs.num_witness_variables() == stats.witnesses, "assignment shape differs from setup");
    let mut inner = cs.borrow_mut().context("missing constraint system")?;
    Ok(Assignment {
        instance: std::mem::take(&mut inner.assignments.instance_assignment),
        witness: std::mem::take(&mut inner.assignments.witness_assignment),
    })
}

fn read_evaluations(input: &mut impl Read, stats: &Stats, assignment: &Assignment) -> Result<Vec<Fr>> {
    let mut values = vec![Fr::ZERO; stats.domain_size];
    for value in &mut values[..stats.constraints] {
        let terms = u32_read(input)?;
        ensure!(terms <= stats.witnesses + stats.public_inputs + 1, "invalid R1CS row length");
        for _ in 0..terms {
            let index = u32_read(input)?;
            let mut tag = [0];
            input.read_exact(&mut tag)?;
            let assigned = assignment.value(index)?;
            match tag[0] {
                0 => *value += assigned,
                1 => *value -= assigned,
                2 => *value += Fr::deserialize_compressed(&mut *input)? * assigned,
                _ => anyhow::bail!("invalid R1CS coefficient tag"),
            }
        }
    }
    Ok(values)
}

/// Same FFT/coset reduction as ark-groth16 0.6 LibsnarkReduction, MIT/Apache-2.0.
/// Only the matrix evaluation source and in-place product differ.
fn quotient(input: &mut impl Read, stats: &Stats, assignment: &Assignment) -> Result<Vec<Fr>> {
    let mut magic = [0; 8];
    input.read_exact(&mut magic)?;
    ensure!(&magic == MAGIC, "invalid R1CS plan");
    ensure!(u32_read(input)? == assignment.instance.len() && u32_read(input)? == assignment.witness.len() && u32_read(input)? == stats.constraints, "R1CS plan shape mismatch");
    let domain = GeneralEvaluationDomain::<Fr>::new(stats.constraints + assignment.instance.len()).context("QAP degree too large")?;
    ensure!(domain.size() == stats.domain_size, "QAP domain mismatch");
    let coset = domain.get_coset(Fr::GENERATOR).context("missing QAP coset")?;
    let mut a = read_evaluations(input, stats, assignment)?;
    a[stats.constraints..stats.constraints + assignment.instance.len()].copy_from_slice(&assignment.instance);
    let mut b = read_evaluations(input, stats, assignment)?;
    domain.ifft_in_place(&mut a);
    domain.ifft_in_place(&mut b);
    coset.fft_in_place(&mut a);
    coset.fft_in_place(&mut b);
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        a.par_iter_mut().zip(b.par_iter()).for_each(|(a, b)| *a *= b);
    }
    #[cfg(not(feature = "parallel"))]
    for (a, b) in a.iter_mut().zip(&b) { *a *= b; }
    drop(b);
    let mut c = read_evaluations(input, stats, assignment)?;
    let mut trailing = [0];
    ensure!(input.read(&mut trailing)? == 0, "trailing R1CS plan bytes");
    domain.ifft_in_place(&mut c);
    coset.fft_in_place(&mut c);
    let vanishing_inverse = domain.evaluate_vanishing_polynomial(Fr::GENERATOR).inverse().context("invalid QAP coset")?;
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        a.par_iter_mut().zip(c.par_iter()).for_each(|(a, c)| *a = (*a - c) * vanishing_inverse);
    }
    #[cfg(not(feature = "parallel"))]
    for (a, c) in a.iter_mut().zip(&c) { *a = (*a - c) * vanishing_inverse; }
    drop(c);
    coset.ifft_in_place(&mut a);
    Ok(a)
}

/// Upstream ark-groth16 0.6 proof equations (MIT/Apache-2.0), without copying the
/// full assignment into a second concatenated scalar vector.
fn proof_from_quotient(pk: &ProvingKey<Bn254>, assignment: Assignment, h: Vec<Fr>) -> Result<Proof<Bn254>> {
    let mut rng = StdRng::from_entropy();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);
    let h_scalars: Vec<_> = h.into_iter().map(|v| v.into_bigint()).collect();
    ensure!(pk.h_query.len() <= h_scalars.len(), "H query shape mismatch");
    let h_acc = G1Projective::msm_bigint(&pk.h_query, &h_scalars[..pk.h_query.len()]);
    drop(h_scalars);
    let witness: Vec<_> = assignment.witness.into_iter().map(|v| v.into_bigint()).collect();
    let inputs: Vec<_> = assignment.instance.into_iter().skip(1).map(|v| v.into_bigint()).collect();
    ensure!(pk.l_query.len() == witness.len(), "L query shape mismatch");
    let l_acc = G1Projective::msm_bigint(&pk.l_query, &witness);
    let split = inputs.len() + 1;
    ensure!(pk.a_query.len() == split + witness.len() && pk.b_g1_query.len() == pk.a_query.len() && pk.b_g2_query.len() == pk.a_query.len(), "A/B query shape mismatch");
    let g1 = |bases: &[G1Affine]| {
        bases[0].into_group() + G1Projective::msm_bigint(&bases[1..split], &inputs) + G1Projective::msm_bigint(&bases[split..], &witness)
    };
    let a = pk.delta_g1 * r + pk.vk.alpha_g1 + g1(&pk.a_query);
    let b1 = pk.delta_g1 * s + pk.beta_g1 + g1(&pk.b_g1_query);
    let b2 = pk.vk.delta_g2 * s + pk.vk.beta_g2 + pk.b_g2_query[0]
        + G2Projective::msm_bigint(&pk.b_g2_query[1..split], &inputs)
        + G2Projective::msm_bigint(&pk.b_g2_query[split..], &witness);
    let c = a * s + b1 * r - pk.delta_g1 * (r * s) + l_acc + h_acc;
    Ok(Proof { a: a.into_affine(), b: b2.into_affine(), c: c.into_affine() })
}

impl Session {
    pub fn new(fixture: LoadedFixture, manifest: Manifest, pk: ProvingKey<Bn254>, vk: VerifyingKey<Bn254>) -> Result<Self> {
        manifest.validate()?;
        ensure!(manifest.relation_id == fixture.relation_id && manifest.pipeline == fixture.pipeline, "key relation differs from fixture");
        ensure!(pk.vk == vk, "proving/verifying keys disagree");
        ensure!(vk.gamma_abc_g1.len() == fixture.expected_public.len() + 1 && manifest.stats.public_inputs == fixture.expected_public.len(), "public key arity differs");
        let pvk = prepare_verifying_key(&vk);
        Ok(Self { fixture, manifest, pk, pvk })
    }

    /// Includes fresh ACVM solving, assignment synthesis, reduction, and randomized proof.
    pub fn prove(&self, mut plan: impl Read) -> Result<Vec<u8>> {
        let assignment = assignments(&self.fixture, &self.manifest.stats)?;
        let h = quotient(&mut plan, &self.manifest.stats, &assignment)?;
        encode(&proof_from_quotient(&self.pk, assignment, h)?)
    }

    pub fn verify(&self, bytes: &[u8]) -> Result<bool> {
        verify(&self.pvk, bytes, &self.fixture.expected_public)
    }

    pub fn verify_public(&self, bytes: &[u8], public: &[Fr]) -> Result<bool> {
        verify(&self.pvk, bytes, public)
    }
}

pub fn verify(key: &PreparedVerifyingKey<Bn254>, bytes: &[u8], expected_public: &[Fr]) -> Result<bool> {
    let proof: Proof<Bn254> = decode(bytes)?;
    Ok(Groth16::<Bn254>::verify_proof(key, &proof, expected_public)?)
}

/// Query storage and the mandatory two live QAP evaluation vectors plus assignment.
/// This is a lower bound, not a success prediction: ACVM, FFT/MSM scratch and
/// allocator fragmentation still have to fit in the same wasm32 linear memory.
pub fn memory_bounds(pk: &ProvingKey<Bn254>, stats: &mut Stats) {
    let g1 = (pk.a_query.len() + pk.b_g1_query.len() + pk.h_query.len() + pk.l_query.len()) as u64;
    let g2 = pk.b_g2_query.len() as u64;
    stats.decoded_query_bytes = g1 * std::mem::size_of::<G1Affine>() as u64 + g2 * std::mem::size_of::<G2Affine>() as u64;
    stats.wasm32_lower_bound_bytes = stats.decoded_query_bytes
        + (2 * stats.domain_size as u64 + stats.witnesses as u64 + stats.public_inputs as u64 + 1) * 32;
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
