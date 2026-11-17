#[cfg(not(target_arch = "wasm32"))]
fn main() -> anyhow::Result<()> {
    use anyhow::{bail, ensure, Context};
    use ark_bn254::Fr;
    use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode, R1CS_PREDICATE_LABEL};
    use passport_groth16::fixture::Fixture;
    use passport_provekit::{decode_proof, fixture_digest, Manifest, Session, Stats, Verifier, COMPILER, REVISION};
    use passport_provekit::PortableBn254 as Bn254Field;
    use provekit_common::{HashConfig, WhirR1CSScheme, WitnessCommitmentMode, R1CS};
    use sha2::{Digest, Sha256};
    use std::{fs::{self, File}, io::{BufReader, BufWriter, Read, Write}, path::PathBuf};

    let args: Vec<String> = std::env::args().skip(1).collect();
    ensure!(args.len() >= 3, "Usage: passport-provekit prepare FIXTURE OUTPUT [THREADS] | prove|verify FIXTURE OUTPUT PROOF [THREADS]");
    let command = args[0].as_str();
    let thread_arg = if command == "prepare" { args.get(3) } else { args.get(4) };
    let default_threads = if command == "verify" { std::thread::available_parallelism()?.get() } else { 1 };
    let threads: usize = thread_arg.map(|s| s.parse()).transpose()?.unwrap_or(default_threads);
    ensure!(threads > 0 && (command.starts_with("verify") || threads == 1 || threads == 6), "Proving supports 1/6 threads; verification requires a positive count");
    rayon::ThreadPoolBuilder::new().num_threads(threads).build_global()?;
    let text = fs::read_to_string(&args[1])?;
    let directory = PathBuf::from(&args[2]);
    if command == "prepare" {
        fs::create_dir_all(&directory)?;
        // Remove readiness before any work, so a failed rebuild is never used.
        let manifest_path = directory.join("manifest.json");
        match fs::remove_file(&manifest_path) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        let fixture = Fixture::parse(&text)?.load()?;
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);
        fixture.relation(None, None).generate_constraints(cs.clone())?;
        cs.finalize();
        let columns = cs.num_instance_variables() + cs.num_witness_variables();
        let public_count = cs.num_instance_variables() - 1;
        let mut matrices = cs.to_matrices()?;
        drop(cs);
        ensure!(matrices.len() == 1, "Unexpected non-R1CS predicate");
        let abc = matrices.remove(R1CS_PREDICATE_LABEL).context("Missing R1CS predicate")?;
        let [a, b, c]: [_; 3] = abc.try_into().map_err(|_| anyhow::anyhow!("Expected A/B/C matrices"))?;
        let rows = a.len();
        ensure!(b.len() == rows && c.len() == rows, "Matrix row mismatch");
        let entries = a.iter().chain(&b).chain(&c).map(Vec::len).sum();
        let mut r1cs = R1CS::<Fr>::new();
        r1cs.add_witnesses(columns);
        r1cs.num_public_inputs = public_count;
        r1cs.reserve_constraints(rows, entries);
        // Consume each Arkworks row after interning: no full matrix clone and
        // no BN254 field serialization/conversion (both engines use ark .6).
        let mut row_a = Vec::new();
        let mut row_b = Vec::new();
        let mut row_c = Vec::new();
        fn canonicalize(row: &mut Vec<(Fr, usize)>) {
            row.sort_unstable_by_key(|(_, column)| *column);
            let mut count = 0;
            for index in 0..row.len() {
                let (coefficient, column) = row[index];
                if count > 0 && row[count - 1].1 == column {
                    row[count - 1].0 += coefficient;
                } else {
                    row[count] = (coefficient, column);
                    count += 1;
                }
            }
            row.truncate(count);
            row.retain(|(coefficient, _)| *coefficient != Fr::from(0u64));
        }
        for ((a, b), c) in a.into_iter().zip(b).zip(c) {
            row_a.clear(); row_b.clear(); row_c.clear();
            for (mut row, output) in [(a, &mut row_a), (b, &mut row_b), (c, &mut row_c)] {
                canonicalize(&mut row);
                for (coefficient, column) in row {
                    output.push((u32::try_from(column)?, r1cs.interner.intern(coefficient)));
                }
            }
            r1cs.push_constraint(row_a.iter().copied(), row_b.iter().copied(), row_c.iter().copied());
        }
        ensure!(r1cs.num_constraints() == rows, "Incomplete matrix conversion");
        let scheme = WhirR1CSScheme::<Bn254Field>::new_for_r1cs(&r1cs, columns, 0, vec![], true,
            HashConfig::Sha256, WitnessCommitmentMode::ZeroKnowledge)?;
        let path = directory.join("r1cs.bin");
        let writer = BufWriter::new(File::create(&path)?);
        let mut writer = postcard::to_io(&r1cs, writer)?;
        writer.flush()?;
        drop(writer);
        drop(r1cs);
        let size = fs::metadata(&path)?.len();
        let mut hash = Sha256::new();
        let mut file = BufReader::new(File::open(&path)?);
        let mut buffer = [0u8; 65536];
        loop {
            let length = file.read(&mut buffer)?;
            if length == 0 { break; }
            hash.update(&buffer[..length]);
        }
        let scheme_bytes = serde_json::to_vec(&scheme)?.len() as u64;
        let manifest = Manifest {
            schema_version: 1, provekit_revision: REVISION.into(), compiler: COMPILER.into(),
            fixture_sha256: fixture_digest(&text)?, r1cs_sha256: hex::encode(hash.finalize()),
            stats: Stats { constraints: rows, witnesses: columns, circuit_bytes: fixture.circuit_bytes as u64,
                prover_key_bytes: size + scheme_bytes, verifier_key_bytes: size + scheme_bytes }, scheme,
        };
        fs::write(manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
        println!("{}", serde_json::to_string(&manifest.stats)?);
        return Ok(());
    }
    ensure!(args.len() >= 4, "Missing proof path");
    if command == "verify" || command == "verify-once" {
        let repeats: usize = args.get(5).map(|value| value.parse()).transpose()?.unwrap_or(20);
        ensure!(repeats > 0, "Verification repeat count must be positive");
        // Key, proof, and expected public statement are loaded/decoded once.
        let verifier = Verifier::new(&text, &fs::read_to_string(directory.join("manifest.json"))?,
            fs::read(directory.join("r1cs.bin"))?)?;
        let proof = decode_proof(&fs::read(&args[3])?)?;
        let start = std::time::Instant::now();
        verifier.verify_decoded(&proof)?;
        let warmup_ms = start.elapsed().as_secs_f64() * 1000.0;
        let mut verify_ms = Vec::with_capacity(if command == "verify" { repeats } else { 0 });
        if command == "verify" {
            for _ in 0..repeats {
                let start = std::time::Instant::now();
                verifier.verify_decoded(&proof)?;
                verify_ms.push(start.elapsed().as_secs_f64() * 1000.0);
            }
        }
        // Report sorted samples so median calculation needs no second vector.
        verify_ms.sort_by(f64::total_cmp);
        let median = if verify_ms.is_empty() { None } else {
            Some((verify_ms[(verify_ms.len() - 1) / 2] + verify_ms[verify_ms.len() / 2]) / 2.0)
        };
        println!("{}", serde_json::json!({"verified": true, "threads": rayon::current_num_threads(),
            "warmup_ms": warmup_ms, "verify_ms": verify_ms, "verify_median_ms": median,
            "measured_repeats": if command == "verify" { repeats } else { 0 }}));
        return Ok(());
    }
    let session = Session::new(&text, &fs::read_to_string(directory.join("manifest.json"))?,
        fs::read(directory.join("r1cs.bin"))?)?;
    match command {
        "prove" => {
            let start = std::time::Instant::now();
            let proof = session.prove()?;
            let elapsed = start.elapsed().as_secs_f64();
            let verify_start = std::time::Instant::now();
            session.verify(&proof)?;
            let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;
            fs::write(&args[3], &proof)?;
            println!("{}", serde_json::json!({"proof_bytes": proof.len(), "prove_seconds": elapsed,
                "prove_ms": elapsed * 1000.0, "verify_ms": verify_ms, "stats": session.stats(),
                "threads": rayon::current_num_threads(), "verified": true,
                "proof_encoding": "postcard binary WHIR transcript", "compression": null}));
        },
        _ => bail!("Unknown command {command}"),
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn main() {}
