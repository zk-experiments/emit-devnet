use anyhow::{ensure, Context, Result};
use ark_bn254::Fr;
use ark_relations::gr1cs::{ConstraintSystem, OptimizationGoal, SynthesisMode};
use passport_groth16::fixture::{Fixture, LoadedFixture};
use portable::{PortableBn254 as Bn254Field, PortableSha256 as TranscriptSponge};
use provekit_common::{PublicInputs, PublicInputsHash, WhirR1CSProof, WhirR1CSScheme, R1CS};
use provekit_prover::WhirR1CSProver;
use provekit_verifier::WhirR1CSVerifier;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use whir::transcript::ProverState;

mod portable;
pub use portable::PortableBn254;

pub const REVISION: &str = "893f6d5866d52124e12c4a90a71c0f4d625f083b";
pub const COMPILER: &str = "1.0.0-rc.5";

#[derive(Serialize, Deserialize)]
pub struct Stats {
    pub constraints: usize,
    pub witnesses: usize,
    pub circuit_bytes: u64,
    pub prover_key_bytes: u64,
    pub verifier_key_bytes: u64,
}

#[derive(Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub provekit_revision: String,
    pub compiler: String,
    pub fixture_sha256: String,
    pub r1cs_sha256: String,
    pub stats: Stats,
    pub scheme: WhirR1CSScheme<Bn254Field>,
}

pub fn fixture_digest(text: &str) -> Result<String> {
    let value: serde_json::Value = serde_json::from_str(text)?;
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&value)?)))
}

fn parse_manifest(fixture: &str, manifest: &str, matrices: &[u8]) -> Result<Manifest> {
    let manifest: Manifest = serde_json::from_str(manifest)?;
    ensure!(manifest.schema_version == 1, "Unsupported ProveKit manifest");
    ensure!(manifest.provekit_revision == REVISION && manifest.compiler == COMPILER,
        "Native/WASM compiler or ProveKit version mismatch");
    ensure!(manifest.fixture_sha256 == fixture_digest(fixture)?, "Prepared fixture mismatch");
    ensure!(manifest.r1cs_sha256 == hex::encode(Sha256::digest(matrices)), "Prepared matrix digest mismatch");
    // Hash serialized bytes directly, without a second matrix serialization.
    ensure!(manifest.scheme.r1cs_hash == provekit_common::R1csHash::new(sha3::Sha3_256::digest(matrices).into()),
        "Prepared circuit hash mismatch");
    ensure!(manifest.scheme.has_public_inputs && manifest.scheme.num_challenges == 0, "Unexpected WHIR statement layout");
    ensure!(matches!(manifest.scheme.hash_config, provekit_common::HashConfig::Sha256),
        "Comparison artifacts require the portable SHA-256 transcript");
    // Deserializing a scheme does not run new_for_r1cs(), which normally
    // registers the BN254 NTT and hash engines. Every native/WASM artifact
    // consumer must initialize the process-local registries before crypto.
    provekit_backend_bn254::register();
    Ok(manifest)
}

pub fn decode_proof(bytes: &[u8]) -> Result<WhirR1CSProof> {
    let (proof, remainder) = postcard::take_from_bytes(bytes)?;
    ensure!(remainder.is_empty(), "Trailing proof bytes");
    Ok(proof)
}

/// Verification-only state: no ACIR decoding, ACVM, witness builders, or PK.
/// ProveKit's non-SPARK verifier still needs the complete R1CS verification key.
pub struct Verifier {
    manifest: Manifest,
    public: PublicInputs<Fr>,
    r1cs: R1CS<Fr>,
}

impl Verifier {
    pub fn new(fixture: &str, manifest: &str, matrices: Vec<u8>) -> Result<Self> {
        let manifest = parse_manifest(fixture, manifest, &matrices)?;
        let fixture = Fixture::parse(fixture)?;
        let public = fixture.expected_public.iter().map(|value| passport_groth16::fixture::parse_field(value))
            .collect::<Result<Vec<_>>>()?;
        let r1cs: R1CS<Fr> = postcard::from_bytes(&matrices)?;
        ensure!(r1cs.num_constraints() == manifest.stats.constraints && r1cs.num_witnesses() == manifest.stats.witnesses
            && r1cs.num_public_inputs == public.len(), "Prepared dimensions mismatch");
        Ok(Self { manifest, public: PublicInputs::from_vec(public), r1cs })
    }
    pub fn stats(&self) -> &Stats { &self.manifest.stats }
    pub fn verify_decoded(&self, proof: &WhirR1CSProof) -> Result<()> {
        self.manifest.scheme.verify(proof, &self.public, &self.r1cs)
    }
    pub fn verify(&self, proof: &[u8]) -> Result<()> { self.verify_decoded(&decode_proof(proof)?) }
}

pub struct Session {
    fixture: LoadedFixture,
    manifest: Manifest,
    // Keep only serialized matrices between calls. In particular, witness
    // generation never holds Arkworks matrices alongside ProveKit matrices.
    matrices: Vec<u8>,
}

impl Session {
    pub fn new(fixture: &str, manifest: &str, matrices: Vec<u8>) -> Result<Self> {
        let manifest = parse_manifest(fixture, manifest, &matrices)?;
        let fixture = Fixture::parse(fixture)?.load()?;
        ensure!(manifest.scheme.has_public_inputs && !fixture.expected_public.is_empty(), "Missing public statement");
        ensure!(manifest.scheme.num_challenges == 0, "Unexpected multi-stage WHIR commitment");
        Ok(Self { fixture, manifest, matrices })
    }

    pub fn stats(&self) -> &Stats { &self.manifest.stats }

    fn decode_matrices(&self) -> Result<R1CS<Fr>> {
        let r1cs: R1CS<Fr> = postcard::from_bytes(&self.matrices).context("Decoding prepared R1CS")?;
        ensure!(r1cs.num_constraints() == self.manifest.stats.constraints
            && r1cs.num_witnesses() == self.manifest.stats.witnesses
            && r1cs.num_public_inputs == self.fixture.expected_public.len(), "Prepared dimensions mismatch");
        Ok(r1cs)
    }

    pub fn prove(&self) -> Result<Vec<u8>> {
        // Fresh rc.5 ACVM execution is part of every measured proving call.
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Prove { construct_matrices: false, generate_lc_assignments: true });
        self.fixture.generate_witness_constraints(cs.clone())?;
        let mut cs = cs.into_inner().context("Outstanding synthesis reference")?;
        ensure!(&cs.assignments.instance_assignment[1..] == self.fixture.expected_public.as_slice(), "Unexpected public assignment");
        let mut assignment = std::mem::take(&mut cs.assignments.witness_assignment);
        assignment.splice(0..0, cs.assignments.instance_assignment.drain(..));
        drop(cs);
        ensure!(assignment.len() == self.manifest.stats.witnesses, "Prepared witness layout mismatch");
        let public = PublicInputs::from_vec(self.fixture.expected_public.clone());
        let scheme = &self.manifest.scheme;
        let instance = public.hash_bytes::<Bn254Field>(scheme.hash_config);
        let ds = scheme.create_domain_separator().instance(&instance);
        let mut transcript = ProverState::new(&ds, TranscriptSponge::from_config(scheme.hash_config));
        // The upstream commitment consumes its vector, but the Spartan stage
        // also needs it; this is the one necessary full assignment copy.
        let commitment = scheme.commit(&mut transcript, assignment.len(), self.manifest.stats.constraints,
            assignment.clone(), true)?;
        let matrices = self.decode_matrices()?;
        let proof = scheme.prove_noir(transcript, matrices, vec![commitment], assignment, &public)?;
        Ok(postcard::to_stdvec(&proof)?)
    }

    pub fn verify(&self, proof: &[u8]) -> Result<()> {
        let proof = decode_proof(proof)?;
        let r1cs = self.decode_matrices()?;
        self.manifest.scheme.verify(&proof, &PublicInputs::from_vec(self.fixture.expected_public.clone()), &r1cs)
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use super::*;
    use wasm_bindgen::prelude::*;

    #[cfg(feature = "threads")]
    pub use wasm_bindgen_rayon::init_thread_pool;

    #[wasm_bindgen(js_name = initSingleThread)]
    pub fn init_single_thread() -> std::result::Result<(), JsError> {
        console_error_panic_hook::set_once();
        rayon::ThreadPoolBuilder::new().num_threads(1).use_current_thread().build_global()
            .map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen(js_name = threadCount)]
    pub fn thread_count() -> usize { rayon::current_num_threads() }

    #[wasm_bindgen(js_name = Session)]
    pub struct BrowserSession(Session);

    #[wasm_bindgen(js_class = Session)]
    impl BrowserSession {
        #[wasm_bindgen(constructor)]
        pub fn new(fixture: &str, manifest: &str, matrices: Vec<u8>) -> std::result::Result<BrowserSession, JsError> {
            console_error_panic_hook::set_once();
            Ok(Self(Session::new(fixture, manifest, matrices).map_err(js_error)?))
        }
        pub fn stats(&self) -> std::result::Result<String, JsError> {
            serde_json::to_string(self.0.stats()).map_err(|e| JsError::new(&e.to_string()))
        }
        pub fn prove(&self) -> std::result::Result<Vec<u8>, JsError> { self.0.prove().map_err(js_error) }
        pub fn verify(&self, proof: &[u8]) -> bool { self.0.verify(proof).is_ok() }
    }

    #[wasm_bindgen(js_name = Verifier)]
    pub struct BrowserVerifier(Verifier);

    #[wasm_bindgen(js_class = Verifier)]
    impl BrowserVerifier {
        #[wasm_bindgen(constructor)]
        pub fn new(fixture: &str, manifest: &str, matrices: Vec<u8>) -> std::result::Result<BrowserVerifier, JsError> {
            console_error_panic_hook::set_once();
            Ok(Self(Verifier::new(fixture, manifest, matrices).map_err(js_error)?))
        }
        pub fn stats(&self) -> std::result::Result<String, JsError> {
            serde_json::to_string(self.0.stats()).map_err(|e| JsError::new(&e.to_string()))
        }
        pub fn verify(&self, proof: &[u8]) -> bool { self.0.verify(proof).is_ok() }
    }

    fn js_error(error: anyhow::Error) -> JsError { JsError::new(&format!("{error:#}")) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use provekit_common::{HashConfig, WitnessCommitmentMode};

    // Run the crypto check in a fresh process after serialized-artifact load:
    // constructing the scheme in this process would hide missing registration.
    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn whir_rejects_wrong_public_and_corrupt_transport() -> Result<()> {
        let (r1cs, scheme): (R1CS<Fr>, WhirR1CSScheme<Bn254Field>) =
            if std::env::var_os("PROVEKIT_DESERIALIZED_TEST_CHILD").is_some() {
                let (manifest, matrices): (String, Vec<u8>) = serde_json::from_reader(std::io::stdin().lock())?;
                let manifest = parse_manifest("{}", &manifest, &matrices)?;
                (postcard::from_bytes(&matrices)?, manifest.scheme)
            } else {
                let mut r1cs = R1CS::<Fr>::new();
                r1cs.add_witnesses(3);
                r1cs.num_public_inputs = 1;
                r1cs.add_constraint(&[(Fr::from(1u64), 2)], &[(Fr::from(1u64), 2)], &[(Fr::from(1u64), 1)]);
                let scheme = WhirR1CSScheme::<Bn254Field>::new_for_r1cs(&r1cs, 3, 0, vec![], true,
                    HashConfig::Sha256, WitnessCommitmentMode::ZeroKnowledge)?;
                let matrices = postcard::to_stdvec(&r1cs)?;
                let manifest = Manifest {
                    schema_version: 1, provekit_revision: REVISION.into(), compiler: COMPILER.into(),
                    fixture_sha256: fixture_digest("{}")?,
                    r1cs_sha256: hex::encode(Sha256::digest(&matrices)),
                    stats: Stats { constraints: 1, witnesses: 3, circuit_bytes: 0,
                        prover_key_bytes: 0, verifier_key_bytes: 0 }, scheme,
                };
                let mut child = std::process::Command::new(std::env::current_exe()?)
                    .args(["--exact", "tests::whir_rejects_wrong_public_and_corrupt_transport", "--nocapture"])
                    .env("PROVEKIT_DESERIALIZED_TEST_CHILD", "1")
                    .stdin(std::process::Stdio::piped()).spawn()?;
                serde_json::to_writer(child.stdin.take().context("Missing child input")?,
                    &(serde_json::to_string(&manifest)?, matrices))?;
                ensure!(child.wait()?.success(), "Fresh-process serialized-artifact proving failed");
                return Ok(());
            };
        let public = PublicInputs::from_vec(vec![Fr::from(9u64)]);
        let instance = public.hash_bytes::<Bn254Field>(scheme.hash_config);
        let ds = scheme.create_domain_separator().instance(&instance);
        let mut transcript = ProverState::new(&ds, TranscriptSponge::from_config(scheme.hash_config));
        let witness = vec![Fr::from(1u64), Fr::from(9u64), Fr::from(3u64)];
        let commitment = scheme.commit(&mut transcript, 3, 1, witness.clone(), true)?;
        let proof = scheme.prove_noir(transcript, r1cs.clone(), vec![commitment], witness, &public)?;
        scheme.verify(&proof, &public, &r1cs)?;
        assert!(scheme.verify(&proof, &PublicInputs::from_vec(vec![Fr::from(10u64)]), &r1cs).is_err());
        let mut corrupt = proof;
        corrupt.narg_string[0] ^= 1;
        assert!(scheme.verify(&corrupt, &public, &r1cs).is_err());
        Ok(())
    }
}
