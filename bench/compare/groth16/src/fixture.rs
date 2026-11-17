use acir::{FieldElement, circuit::{Circuit, Opcode, Program, opcodes::{BlockType, MemOpKind}}, native_types::{Witness, WitnessMap}};
use acvm::pwg::{ACVM, ACVMStatus};
use anyhow::{Context, Result, ensure};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use base64::Engine;
use bn254_blackbox_solver::Bn254BlackBoxSolver;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use crate::circuit::{Relation, Step};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Link {
    pub from: [usize; 2],
    pub to: [usize; 2],
}

#[derive(Deserialize)]
pub struct Artifact {
    pub abi: serde_json::Value,
    pub bytecode: String,
}

#[derive(Deserialize)]
pub struct App {
    pub name: String,
    pub artifact: Artifact,
    pub inputs_toml: String,
    pub initial_witness: Vec<(u32, String)>,
    pub output_witnesses: Vec<u32>,
    pub expected_outputs: Vec<String>,
}

#[derive(Deserialize)]
pub struct Fixture {
    pub schema_version: u32,
    pub pipeline: String,
    pub kind: String,
    pub apps: Vec<App>,
    pub links: Vec<Link>,
    pub public_outputs: Vec<[usize; 2]>,
    pub expected_public: Vec<String>,
}

pub struct LoadedApp {
    pub program: Program<FieldElement>,
    pub initial_witness: WitnessMap<FieldElement>,
    pub outputs: Vec<Witness>,
    pub expected_outputs: Vec<Fr>,
}

pub struct LoadedFixture {
    pub pipeline: String,
    pub relation_id: String,
    pub circuit_bytes: usize,
    pub apps: Vec<LoadedApp>,
    pub links: Vec<Link>,
    pub public_outputs: Vec<[usize; 2]>,
    pub expected_public: Vec<Fr>,
}

pub fn parse_field(text: &str) -> Result<Fr> {
    let bytes = hex::decode(text.strip_prefix("0x").context("field must have 0x prefix")?)?;
    ensure!(bytes.len() == 32, "field must contain exactly 32 bytes");
    let value = Fr::from_be_bytes_mod_order(&bytes);
    ensure!(value.into_bigint().to_bytes_be() == bytes, "noncanonical BN254 field");
    Ok(value)
}

pub fn field_string(value: &Fr) -> String {
    format!("0x{}", hex::encode(value.into_bigint().to_bytes_be()))
}

/// The same flattened type layout used by noir-zk's ABI encoder. Checked
/// arithmetic also prevents malformed ABI lengths from aliasing witness indices.
fn abi_field_count(value: &serde_json::Value) -> Result<usize> {
    match value["kind"].as_str() {
        Some("field" | "boolean") => Ok(1),
        Some("integer") if value["sign"] == "unsigned" && value["width"].as_u64().is_some() => Ok(1),
        Some("array") => {
            let length = usize::try_from(value["length"].as_u64().context("ABI array without length")?)?;
            length.checked_mul(abi_field_count(&value["type"])?).context("ABI array field count overflow")
        }
        Some("struct") => value["fields"].as_array().context("ABI struct without fields")?
            .iter().try_fold(0usize, |total, field| {
                total.checked_add(abi_field_count(&field["type"])?).context("ABI struct field count overflow")
            }),
        _ => anyhow::bail!("unsupported ABI type: {value}"),
    }
}

fn app_outputs(app: &App, circuit: &Circuit<FieldElement>, parameters: &BTreeSet<Witness>) -> Result<Vec<Witness>> {
    let abi = &app.artifact.abi;
    ensure!(abi["abi_version"] == 1, "unsupported ABI version");
    let inputs = abi["parameters"].as_array().context("ABI has no parameters")?
        .iter().try_fold(0usize, |total, parameter| {
            total.checked_add(abi_field_count(&parameter["type"])?).context("ABI input field count overflow")
        })?;
    let inputs = u32::try_from(inputs)?;
    let returns = u32::try_from(abi_field_count(&abi["return_type"]["abi_type"])?)?;
    let end = inputs.checked_add(returns).context("ABI output witness overflow")?;
    ensure!(parameters.iter().copied().eq((0..inputs).map(Witness)), "ACIR parameters differ from canonical ABI input layout");
    ensure!(app.output_witnesses.iter().copied().eq(inputs..end), "output witnesses differ from ordered ABI return layout");
    let outputs: Vec<_> = (inputs..end).map(Witness).collect();
    let mut databus = circuit.opcodes.iter().filter_map(|opcode| match opcode {
        Opcode::MemoryInit { block_id, init, block_type: BlockType::ReturnData } => Some((block_id, init)),
        _ => None,
    });
    match abi["return_type"]["visibility"].as_str() {
        Some("databus") => {
            let (block_id, init) = databus.next().context("ABI databus return has no ACIR ReturnData block")?;
            ensure!(databus.next().is_none(), "multiple ACIR ReturnData blocks");
            ensure!(init == &outputs, "ACIR ReturnData witnesses differ from ordered ABI returns");
            ensure!(circuit.return_values.0.is_empty(), "databus return also declares ordinary ACIR returns");
            ensure!(!circuit.opcodes.iter().any(|opcode| matches!(opcode,
                Opcode::MemoryOp { block_id: id, op } if id == block_id && op.operation == MemOpKind::Write
            )), "mutable ACIR ReturnData block");
        }
        Some("public") => {
            ensure!(databus.next().is_none(), "ordinary ABI return also declares ACIR ReturnData");
            ensure!(circuit.return_values.0.iter().copied().eq(outputs.iter().copied()), "ACIR public returns differ from ABI returns");
        }
        _ => anyhow::bail!("unsupported ABI return visibility"),
    }
    Ok(outputs)
}

impl Fixture {
    pub fn parse(text: &str) -> Result<Self> {
        let fixture: Self = serde_json::from_str(text)?;
        fixture.validate()?;
        Ok(fixture)
    }

    fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == 1, "unsupported fixture schema");
        ensure!(self.public_outputs.len() == self.expected_public.len(), "public arity mismatch");
        ensure!(!self.public_outputs.is_empty(), "empty public statement");
        match self.kind.as_str() {
            "registration" => {
                ensure!(matches!(self.pipeline.as_str(), "identity_register_de_bp384_bp256" | "identity_register_us_rsa4096_rsa2048"), "unknown registration pipeline");
                ensure!(self.apps.len() == 4, "registration must contain all four ordered apps");
                ensure!(self.apps.iter().map(|a| a.output_witnesses.len()).eq([2, 2, 5, 3]), "registration record layout differs");
                ensure!(self.links == [
                    Link { from: [0, 1], to: [1, 0] },
                    Link { from: [1, 1], to: [2, 0] },
                    Link { from: [2, 1], to: [3, 0] },
                ], "registration must enforce all three private links");
                ensure!(self.public_outputs == [[0, 0], [2, 2], [2, 3], [2, 4], [3, 1], [3, 2]], "registration public statement differs");
            }
            "age" => {
                ensure!(self.pipeline == "age_verify" && self.apps.len() == 1 && self.links.is_empty(), "age must contain one app");
            }
            _ => anyhow::bail!("unknown fixture kind"),
        }
        for app in &self.apps {
            ensure!(app.output_witnesses.len() == app.expected_outputs.len(), "output arity mismatch");
        }
        for point in self.public_outputs.iter().chain(self.links.iter().flat_map(|l| [&l.from, &l.to])) {
            ensure!(self.apps.get(point[0]).and_then(|a| a.output_witnesses.get(point[1])).is_some(), "output mapping out of bounds");
        }
        Ok(())
    }

    fn relation_digest(&self) -> Result<Sha256> {
        let mut digest = Sha256::new();
        digest.update(b"passport-groth16/rc5/relation/v1");
        digest.update(serde_json::to_vec(&(&self.pipeline, &self.links, &self.public_outputs))?);
        Ok(digest)
    }

    fn hash_app(digest: &mut Sha256, app: &App, bytes: &[u8]) -> Result<()> {
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
        digest.update(serde_json::to_vec(&app.output_witnesses)?);
        Ok(())
    }

    /// Key binding for verification-only clients, without deserializing ACIR.
    pub fn relation_id(&self) -> Result<String> {
        self.validate()?;
        let mut digest = self.relation_digest()?;
        for app in &self.apps {
            let bytes = base64::engine::general_purpose::STANDARD.decode(app.artifact.bytecode.trim())?;
            Self::hash_app(&mut digest, app, &bytes)?;
        }
        Ok(hex::encode(digest.finalize()))
    }

    pub fn load(&self) -> Result<LoadedFixture> {
        self.validate()?;
        let mut digest = self.relation_digest()?;
        let mut circuit_bytes = 0;
        let mut apps = Vec::with_capacity(self.apps.len());
        for app in &self.apps {
            let bytes = base64::engine::general_purpose::STANDARD.decode(app.artifact.bytecode.trim())?;
            circuit_bytes += bytes.len();
            Self::hash_app(&mut digest, app, &bytes)?;
            let program = Program::deserialize_program(&bytes)?;
            ensure!(program.functions.len() == 1, "{}: expected flattened ACIR function", app.name);
            let circuit = &program.functions[0];
            let parameters: BTreeSet<_> = circuit.private_parameters.iter().chain(&circuit.public_parameters.0).copied().collect();
            let outputs = app_outputs(app, circuit, &parameters)
                .with_context(|| format!("{}: invalid ABI/ACIR output layout", app.name))?;
            let mut initial_witness = WitnessMap::new();
            for (index, text) in &app.initial_witness {
                let witness = Witness(*index);
                ensure!(parameters.contains(&witness), "{}: saved non-input witness forbidden", app.name);
                ensure!(initial_witness.get(&witness).is_none(), "duplicate input witness");
                initial_witness.insert(witness, FieldElement::from_repr(parse_field(text)?));
            }
            ensure!(parameters.iter().all(|w| initial_witness.get(w).is_some()), "missing ACIR input assignment");
            apps.push(LoadedApp {
                program, initial_witness, outputs,
                expected_outputs: app.expected_outputs.iter().map(|v| parse_field(v)).collect::<Result<_>>()?,
            });
        }
        let expected_public = self.expected_public.iter().map(|v| parse_field(v)).collect::<Result<Vec<_>>>()?;
        for (point, expected) in self.public_outputs.iter().zip(&expected_public) {
            ensure!(apps[point[0]].expected_outputs[point[1]] == *expected, "expected public mapping mismatch");
        }
        for link in &self.links {
            ensure!(apps[link.from[0]].expected_outputs[link.from[1]] == apps[link.to[0]].expected_outputs[link.to[1]], "expected fixture links disagree");
        }
        Ok(LoadedFixture {
            pipeline: self.pipeline.clone(), relation_id: hex::encode(digest.finalize()), circuit_bytes,
            apps, links: self.links.clone(), public_outputs: self.public_outputs.clone(), expected_public,
        })
    }
}

impl LoadedApp {
    pub fn solve(&self) -> Result<WitnessMap<FieldElement>> {
        let circuit = &self.program.functions[0];
        let solver = Bn254BlackBoxSolver;
        let mut acvm = ACVM::new(&solver, &circuit.opcodes, self.initial_witness.clone(),
            &self.program.unconstrained_functions, &circuit.assert_messages);
        ensure!(matches!(acvm.solve(), ACVMStatus::Solved), "ACVM rejected witness: {}", acvm.get_status());
        Ok(acvm.finalize())
    }
}

impl LoadedFixture {
    /// Only initial ABI inputs are saved. ACVM executes every Brillig hint again.
    pub fn solve(&self) -> Result<Vec<WitnessMap<FieldElement>>> {
        self.apps.iter().map(LoadedApp::solve).collect()
    }

    /// Solve and synthesize one app at a time, dropping each ACVM witness map
    /// immediately. Allocation order is identical to relation().generate_constraints().
    pub fn generate_witness_constraints(&self, cs: ark_relations::gr1cs::ConstraintSystemRef<Fr>) -> Result<()> {
        let public = crate::circuit::allocate_public(cs.clone(), self.public_outputs.len(), Some(&self.expected_public))?;
        let records = self.apps.iter().map(|app| {
            let witness = app.solve()?;
            Ok(crate::circuit::synthesize_step(cs.clone(), &Step {
                circuit: &app.program.functions[0], witness: Some(&witness), outputs: app.outputs.clone(),
            })?)
        }).collect::<Result<Vec<_>>>()?;
        Ok(crate::circuit::bind_records(&records, &self.links, &self.public_outputs, &public)?)
    }

    pub fn relation<'a>(&'a self, witnesses: Option<&'a [WitnessMap<FieldElement>]>, public: Option<&'a [Fr]>) -> Relation<'a> {
        Relation {
            steps: self.apps.iter().enumerate().map(|(i, app)| Step {
                circuit: &app.program.functions[0], witness: witnesses.map(|maps| &maps[i]), outputs: app.outputs.clone(),
            }).collect(),
            links: &self.links, public_outputs: &self.public_outputs, public,
        }
    }
}
