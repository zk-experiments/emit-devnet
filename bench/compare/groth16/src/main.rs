use anyhow::{Context, Result, ensure};
use ark_bn254::Bn254;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey, prepare_verifying_key};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, R1CS_PREDICATE_LABEL, SynthesisMode};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{SeedableRng, rngs::StdRng};
use passport_groth16::{engine::{self, Manifest, Session, Stats}, fixture::{Fixture, field_string, parse_field}};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs::{self, File}, io::{BufReader, BufWriter, Read, Write}, path::Path, time::Instant};

fn save(path: &Path, value: &impl CanonicalSerialize) -> Result<u64> {
    let mut output = BufWriter::new(File::create_new(path)?);
    value.serialize_compressed(&mut output)?;
    output.flush()?;
    Ok(output.get_ref().metadata()?.len())
}

fn read<T: CanonicalDeserialize>(path: &Path) -> Result<T> {
    engine::decode(BufReader::new(File::open(path)?))
}

fn hash(path: &Path) -> Result<String> {
    let mut file = BufReader::new(File::open(path)?);
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 { break; }
        digest.update(&buffer[..n]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn load(fixture: &Path, directory: &Path) -> Result<Session> {
    let fixture = Fixture::parse(&fs::read_to_string(fixture)?)?.load()?;
    let manifest: Manifest = serde_json::from_slice(&fs::read(directory.join("manifest.json"))?)?;
    manifest.validate()?;
    for (name, digest) in &manifest.sha256 {
        ensure!(hash(&directory.join(&manifest.files[name]))? == *digest, "artifact hash mismatch: {name}");
    }
    let pk: ProvingKey<Bn254> = read(&directory.join(&manifest.files["pk"]))?;
    let vk = read(&directory.join(&manifest.files["vk"]))?;
    Session::new(fixture, manifest, pk, vk)
}

fn setup(fixture_path: &Path, directory: &Path) -> Result<serde_json::Value> {
    let start = Instant::now();
    let fixture = Fixture::parse(&fs::read_to_string(fixture_path)?)?.load()?;
    fs::create_dir_all(directory)?;
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    fixture.relation(None, None).generate_constraints(cs.clone())?;
    let mut stats = Stats {
        constraints: cs.num_constraints(), witnesses: cs.num_witness_variables(),
        public_inputs: cs.num_instance_variables() - 1, circuit_bytes: fixture.circuit_bytes,
        prover_key_bytes: 0, verifier_key_bytes: 0, matrix_plan_bytes: 0,
        domain_size: GeneralEvaluationDomain::<ark_bn254::Fr>::new(cs.num_constraints() + cs.num_instance_variables()).context("QAP degree too large")?.size(),
        decoded_query_bytes: 0, wasm32_lower_bound_bytes: 0,
    };
    cs.finalize();
    let mut matrices = cs.to_matrices()?;
    drop(cs);
    let matrices = matrices.remove(R1CS_PREDICATE_LABEL).context("missing R1CS matrices")?;
    let mut output = BufWriter::new(File::create_new(directory.join("r1cs.bin"))?);
    engine::write_plan(&mut output, &matrices, &stats)?;
    output.flush()?;
    stats.matrix_plan_bytes = output.get_ref().metadata()?.len();
    drop(output);
    drop(matrices);
    // Drop the export matrices before generating a second setup CS and the huge PK.
    let mut rng = StdRng::from_entropy();
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(fixture.relation(None, None), &mut rng)?;
    engine::memory_bounds(&pk, &mut stats);
    stats.prover_key_bytes = save(&directory.join("pk.bin"), &pk)?;
    stats.verifier_key_bytes = save(&directory.join("vk.bin"), &pk.vk)?;
    drop(pk);
    let files = BTreeMap::from([
        ("pk".to_owned(), "pk.bin".to_owned()),
        ("vk".to_owned(), "vk.bin".to_owned()),
        ("r1cs".to_owned(), "r1cs.bin".to_owned()),
    ]);
    let mut sha256 = BTreeMap::new();
    for (name, file) in &files { sha256.insert(name.clone(), hash(&directory.join(file))?); }
    let manifest = Manifest {
        schema_version: 1, backend: "arkworks-groth16-bn254".into(), noir_version: "1.0.0-rc.5".into(),
        pipeline: fixture.pipeline.clone(), relation_id: fixture.relation_id.clone(),
        setup: "LOCAL RANDOM TEST SETUP; NOT A PRODUCTION CEREMONY".into(), stats, files, sha256,
    };
    fs::write(directory.join("public.json"), serde_json::to_vec_pretty(&fixture.expected_public.iter().map(field_string).collect::<Vec<_>>())?)?;
    fs::write(directory.join("manifest.json"), serde_json::to_vec_pretty(&manifest)?)?;
    Ok(json!({"operation":"setup", "elapsed_ms":start.elapsed().as_secs_f64()*1000.0, "manifest":manifest}))
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    #[cfg(feature = "parallel")]
    let threads = rayon::current_num_threads();
    #[cfg(not(feature = "parallel"))]
    let threads = 1;
    let result = match args.first().map(String::as_str) {
        Some("setup") if args.len() == 3 => setup(Path::new(&args[1]), Path::new(&args[2]))?,
        Some("prove") if args.len() == 4 => {
            let session = load(Path::new(&args[1]), Path::new(&args[2]))?;
            let start = Instant::now();
            let proof = session.prove(BufReader::new(File::open(Path::new(&args[2]).join(&session.manifest.files["r1cs"]))?))?;
            let prove_ms = start.elapsed().as_secs_f64()*1000.0;
            let start = Instant::now();
            ensure!(session.verify(&proof)?, "Groth16 rejected generated proof");
            let verify_ms = start.elapsed().as_secs_f64()*1000.0;
            fs::write(&args[3], &proof)?;
            let decoded: Proof<Bn254> = engine::decode(proof.as_slice())?;
            json!({"operation":"prove", "verified":true, "threads":threads, "prove_ms":prove_ms, "verify_ms":verify_ms, "proof_bytes":proof.len(), "proof_uncompressed_bytes":decoded.uncompressed_size(), "proof_encoding":"arkworks-canonical-point-compressed", "compression":null, "stats":session.manifest.stats})
        }
        Some("verify") if args.len() == 4 || args.len() == 5 => {
            let vk: VerifyingKey<Bn254> = read(Path::new(&args[1]))?;
            let public: Vec<String> = serde_json::from_slice(&fs::read(&args[2])?)?;
            let public = public.iter().map(|v| parse_field(v)).collect::<Result<Vec<_>>>()?;
            let proof_bytes = fs::read(&args[3])?;
            let proof: Proof<Bn254> = engine::decode(proof_bytes.as_slice())?;
            let pvk = prepare_verifying_key(&vk);
            let count = args.get(4).map(|v| v.parse::<usize>()).transpose()?.unwrap_or(20);
            ensure!(count > 0, "verify sample count must be positive");
            let start = Instant::now();
            ensure!(Groth16::<Bn254>::verify_proof(&pvk, &proof, &public)?, "Groth16 warm-up verification failed");
            let warmup_ms = start.elapsed().as_secs_f64()*1000.0;
            let mut samples = Vec::with_capacity(count);
            for _ in 0..count {
                let start = Instant::now();
                let valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public)?;
                samples.push(start.elapsed().as_secs_f64()*1000.0);
                ensure!(valid, "Groth16 verification failed");
            }
            let mut ordered = samples.clone();
            ordered.sort_by(f64::total_cmp);
            let middle = count / 2;
            let median = if count % 2 == 0 { (ordered[middle - 1] + ordered[middle]) / 2.0 } else { ordered[middle] };
            json!({"operation":"verify", "verified":true, "verify_samples_ms":samples, "verify_median_ms":median, "warmup_ms":warmup_ms, "threads":threads, "proof_bytes":proof_bytes.len(), "proof_uncompressed_bytes":proof.uncompressed_size(), "proof_encoding":"arkworks-canonical-point-compressed", "compression":null, "public_inputs":public.len()})
        }
        _ => anyhow::bail!("usage: passport-groth16 setup FIXTURE OUTPUT_DIR | prove FIXTURE KEY_DIR PROOF_BIN | verify VK_BIN EXPECTED_PUBLIC_JSON PROOF_BIN [SAMPLES=20]"),
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
