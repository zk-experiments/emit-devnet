use super::*;
use acir::{AcirField, FieldElement, circuit::{Circuit, Opcode, Program, opcodes::{BlockId, BlockType, MemOp}}, native_types::{Expression, Witness, WitnessMap}};
use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
use ark_relations::gr1cs::{ConstraintSynthesizer, R1CS_PREDICATE_LABEL};
use base64::Engine;
use crate::fixture::{Fixture, LoadedApp, field_string};

fn fixture() -> LoadedFixture {
    let square = Expression {
        mul_terms: vec![(FieldElement::one(), Witness(0), Witness(0))],
        linear_combinations: vec![(-FieldElement::one(), Witness(1))],
        q_c: FieldElement::zero(),
    };
    let add = Expression {
        mul_terms: vec![],
        linear_combinations: vec![(FieldElement::one(), Witness(0)), (-FieldElement::one(), Witness(2))],
        q_c: FieldElement::from(7u64),
    };
    let circuit = Circuit {
        opcodes: vec![
            Opcode::AssertZero(square), Opcode::AssertZero(add),
            Opcode::MemoryInit { block_id: BlockId::new(0), init: vec![Witness(1), Witness(2)], block_type: BlockType::ReturnData },
        ],
        private_parameters: [Witness(0)].into_iter().collect(),
        ..Circuit::default()
    };
    let mut initial_witness = WitnessMap::new();
    initial_witness.insert(Witness(0), FieldElement::from(3u64));
    LoadedFixture {
        pipeline: "age_verify".into(), relation_id: "test-relation".into(), circuit_bytes: 0,
        apps: vec![LoadedApp {
            program: Program { functions: vec![circuit], unconstrained_functions: vec![] },
            initial_witness, outputs: vec![Witness(1), Witness(2)], expected_outputs: vec![Fr::from(9), Fr::from(10)],
        }],
        links: vec![], public_outputs: vec![[0, 1], [0, 0]], expected_public: vec![Fr::from(10), Fr::from(9)],
    }
}

fn comparison_fixture(program: &Program<FieldElement>) -> serde_json::Value {
    let bytecode = base64::engine::general_purpose::STANDARD.encode(Program::serialize_program(program));
    serde_json::json!({
        "schema_version":1, "pipeline":"age_verify", "kind":"age",
        "apps":[{"name":"age", "artifact":{"abi":{
            "abi_version":1,
            "parameters":[{"name":"x","type":{"kind":"field"},"visibility":"private"}],
            "return_type":{"abi_type":{"kind":"array","length":2,"type":{"kind":"field"}},"visibility":"databus"}
        }, "bytecode":bytecode}, "inputs_toml":"",
            "initial_witness":[[0,field_string(&Fr::from(3))]], "output_witnesses":[1,2],
            "expected_outputs":[field_string(&Fr::from(9)),field_string(&Fr::from(10))]}],
        "links":[], "public_outputs":[[0,1],[0,0]], "expected_public":[field_string(&Fr::from(10)),field_string(&Fr::from(9))]
    })
}

fn setup(fixture: &LoadedFixture) -> (Stats, Vec<ark_relations::gr1cs::Matrix<Fr>>) {
    let cs = ConstraintSystem::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    fixture.relation(None, None).generate_constraints(cs.clone()).unwrap();
    let stats = Stats {
        constraints: cs.num_constraints(), witnesses: cs.num_witness_variables(), public_inputs: cs.num_instance_variables() - 1,
        circuit_bytes: 0, prover_key_bytes: 0, verifier_key_bytes: 0, matrix_plan_bytes: 0,
        domain_size: GeneralEvaluationDomain::<Fr>::new(cs.num_constraints() + cs.num_instance_variables()).unwrap().size(),
        decoded_query_bytes: 0, wasm32_lower_bound_bytes: 0,
    };
    cs.finalize();
    (stats, cs.to_matrices().unwrap().remove(R1CS_PREDICATE_LABEL).unwrap())
}

#[test]
fn witness_only_assignment_and_streamed_reduction_match_arkworks() {
    let fixture = fixture();
    let (stats, matrices) = setup(&fixture);
    let assignment = assignments(&fixture, &stats).unwrap();
    let maps = fixture.solve().unwrap();
    let full = ConstraintSystem::new_ref();
    full.set_optimization_goal(OptimizationGoal::Constraints);
    fixture.relation(Some(&maps), Some(&fixture.expected_public)).generate_constraints(full.clone()).unwrap();
    assert!(full.is_satisfied().unwrap());
    assert_eq!(assignment.instance, full.instance_assignment().unwrap());
    assert_eq!(assignment.witness, full.witness_assignment().unwrap());
    full.finalize();
    assert_eq!(matrices, full.to_matrices().unwrap().remove(R1CS_PREDICATE_LABEL).unwrap());
    let mut plan = vec![];
    write_plan(&mut plan, &matrices, &stats).unwrap();
    let streamed = quotient(&mut plan.as_slice(), &stats, &assignment).unwrap();
    let mut concatenated = assignment.instance.clone();
    concatenated.extend_from_slice(&assignment.witness);
    let upstream = LibsnarkReduction::witness_map_from_matrices::<Fr, GeneralEvaluationDomain<Fr>>(
        &matrices, stats.public_inputs + 1, stats.constraints, &concatenated,
    ).unwrap();
    assert_eq!(streamed, upstream);
    let mut rng = StdRng::seed_from_u64(99);
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(fixture.relation(None, None), &mut rng).unwrap();
    let proof = proof_from_quotient(&pk, assignment, streamed).unwrap();
    let pvk = prepare_verifying_key(&pk.vk);
    let encoded = encode(&proof).unwrap();
    assert_eq!(encoded.len(), 128);
    assert!(verify(&pvk, &encoded, &fixture.expected_public).unwrap());
    for i in 0..fixture.expected_public.len() {
        let mut changed = fixture.expected_public.clone();
        changed[i] += Fr::ONE;
        assert!(!verify(&pvk, &encoded, &changed).unwrap());
    }
    assert!(!verify(&pvk, &encoded, &fixture.expected_public[..1]).unwrap_or(false));
    assert!(verify(&pvk, &encoded[..127], &fixture.expected_public).is_err());
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(verify(&pvk, &trailing, &fixture.expected_public).is_err());
    let mut corrupted = encoded;
    corrupted[0] ^= 1;
    assert!(!verify(&pvk, &corrupted, &fixture.expected_public).unwrap_or(false));
    assert!(quotient(&mut &plan[..plan.len() - 1], &stats, &assignments(&fixture, &stats).unwrap()).is_err());
}

#[test]
fn acvm_is_executed_again_and_saved_internal_assignments_are_rejected() {
    let mut loaded = fixture();
    assert_eq!(loaded.solve().unwrap()[0][&Witness(1)], FieldElement::from(9u64));
    loaded.apps[0].initial_witness.insert(Witness(0), FieldElement::from(4u64));
    assert_eq!(loaded.solve().unwrap()[0][&Witness(1)], FieldElement::from(16u64));
    let fixture = fixture();
    let mut json = comparison_fixture(&fixture.apps[0].program);
    let parsed = Fixture::parse(&json.to_string()).unwrap();
    assert_eq!(parsed.relation_id().unwrap(), parsed.load().unwrap().relation_id);
    json["apps"][0]["initial_witness"].as_array_mut().unwrap().push(serde_json::json!([1,field_string(&Fr::from(9))]));
    assert!(Fixture::parse(&json.to_string()).unwrap().load().is_err());
}

#[test]
fn fixture_contract_and_canonical_public_fields_are_strict() {
    assert!(crate::fixture::parse_field(&format!("0x{}", "ff".repeat(32))).is_err());
    assert!(crate::fixture::parse_field("0x01").is_err());
    let names = ["dsc", "sod", "document", "register"];
    let apps = [2usize, 2, 5, 3].into_iter().enumerate().map(|(i, n)| serde_json::json!({
        "name":names[i], "artifact":{"abi":{},"bytecode":""},
        "inputs_toml":"", "initial_witness":[], "output_witnesses":(0..n).collect::<Vec<_>>(),
        "expected_outputs":vec![field_string(&Fr::ZERO);n]
    })).collect::<Vec<_>>();
    let mut json = serde_json::json!({
        "schema_version":1, "pipeline":"identity_register_de_bp384_bp256", "kind":"registration",
        "apps":apps,
        "links":[{"from":[0,1],"to":[1,0]},{"from":[1,1],"to":[2,0]},{"from":[2,1],"to":[3,0]}],
        "public_outputs":[[0,0],[2,2],[2,3],[2,4],[3,1],[3,2]], "expected_public":vec![field_string(&Fr::ZERO);6]
    });
    assert!(Fixture::parse(&json.to_string()).is_ok());
    for i in 0..3 {
        let mut broken = json.clone();
        broken["links"].as_array_mut().unwrap().remove(i);
        assert!(Fixture::parse(&broken.to_string()).is_err());
    }
    json["public_outputs"][0] = serde_json::json!([0,1]);
    assert!(Fixture::parse(&json.to_string()).is_err());
}

#[test]
fn rc5_databus_outputs_require_matching_abi_and_immutable_return_metadata() {
    let program = fixture().apps.remove(0).program;
    let original = comparison_fixture(&program);
    let loaded = Fixture::parse(&original.to_string()).unwrap().load().unwrap();
    assert!(loaded.apps[0].program.functions[0].return_values.0.is_empty());
    assert_eq!(loaded.apps[0].outputs, [Witness(1), Witness(2)]);
    let maps = loaded.solve().unwrap();
    assert_eq!(maps[0][&Witness(1)], FieldElement::from(9u64));
    let reject = |program: &Program<FieldElement>| {
        let json = comparison_fixture(program);
        assert!(Fixture::parse(&json.to_string()).unwrap().load().is_err());
    };
    let mut missing = program.clone();
    missing.functions[0].opcodes.pop();
    reject(&missing);
    let mut unmarked = program.clone();
    let Opcode::MemoryInit { block_type, .. } = unmarked.functions[0].opcodes.last_mut().unwrap() else { unreachable!() };
    *block_type = BlockType::Memory;
    reject(&unmarked);
    let mut reordered = program.clone();
    let Opcode::MemoryInit { init, .. } = reordered.functions[0].opcodes.last_mut().unwrap() else { unreachable!() };
    init.swap(0, 1);
    reject(&reordered);
    let mut duplicate = program.clone();
    duplicate.functions[0].opcodes.push(Opcode::MemoryInit {
        block_id: BlockId::new(1), init: vec![Witness(1), Witness(2)], block_type: BlockType::ReturnData,
    });
    reject(&duplicate);
    let mut mutable = program.clone();
    mutable.functions[0].opcodes.push(Opcode::MemoryOp {
        block_id: BlockId::new(0), op: MemOp::write_to_mem_index(Witness(0), Witness(1)),
    });
    reject(&mutable);
    let mut mixed = program.clone();
    mixed.functions[0].return_values.0 = [Witness(1), Witness(2)].into_iter().collect();
    reject(&mixed);
    let mut wrong_witnesses = original.clone();
    wrong_witnesses["apps"][0]["output_witnesses"] = serde_json::json!([2,1]);
    assert!(Fixture::parse(&wrong_witnesses.to_string()).unwrap().load().is_err());
    let mut wrong_count = original.clone();
    wrong_count["apps"][0]["artifact"]["abi"]["return_type"]["abi_type"]["length"] = 1.into();
    assert!(Fixture::parse(&wrong_count.to_string()).unwrap().load().is_err());
    let mut wrong_inputs = original.clone();
    wrong_inputs["apps"][0]["artifact"]["abi"]["parameters"][0]["type"] = serde_json::json!({"kind":"array","length":2,"type":{"kind":"field"}});
    assert!(Fixture::parse(&wrong_inputs.to_string()).unwrap().load().is_err());
    let mut nested = original.clone();
    nested["apps"][0]["artifact"]["abi"]["parameters"][0]["type"] = serde_json::json!({
        "kind":"struct","fields":[{"name":"items","type":{"kind":"array","length":1,"type":{"kind":"field"}}}]
    });
    assert!(Fixture::parse(&nested.to_string()).unwrap().load().is_ok());
    let mut public = missing;
    public.functions[0].return_values.0 = [Witness(1), Witness(2)].into_iter().collect();
    let mut public_json = comparison_fixture(&public);
    public_json["apps"][0]["artifact"]["abi"]["return_type"]["visibility"] = "public".into();
    assert!(Fixture::parse(&public_json.to_string()).unwrap().load().is_ok());
    public.functions[0].return_values.0.remove(&Witness(2));
    public_json["apps"][0]["artifact"]["bytecode"] = base64::engine::general_purpose::STANDARD.encode(Program::serialize_program(&public)).into();
    assert!(Fixture::parse(&public_json.to_string()).unwrap().load().is_err());
}

#[cfg(feature = "parallel")]
#[test]
fn upstream_msm_matches_naive_g1_and_g2() {
    use ark_ec::PrimeGroup;
    let mut rng = StdRng::seed_from_u64(0x70697070656e6765);
    for size in [0usize, 1, 7, 65, 129] {
        let scalars: Vec<_> = (0..size).map(|i| match i % 8 {
            0 => Fr::ZERO,
            1 => Fr::ONE,
            2 => -Fr::ONE,
            3 => Fr::from(u64::MAX),
            4 => -Fr::from(1u128 << 100),
            _ => Fr::rand(&mut rng),
        }.into_bigint()).collect();
        let g1: Vec<_> = (0..size).map(|i| (G1Projective::generator() * Fr::from(i as u64 + 1)).into_affine()).collect();
        let g2: Vec<_> = (0..size).map(|i| (G2Projective::generator() * Fr::from(i as u64 + 1)).into_affine()).collect();
        let expected_g1 = g1.iter().zip(&scalars).fold(G1Projective::ZERO, |sum, (base, scalar)| sum + base.mul_bigint(*scalar));
        let expected_g2 = g2.iter().zip(&scalars).fold(G2Projective::ZERO, |sum, (base, scalar)| sum + base.mul_bigint(*scalar));
        assert_eq!(G1Projective::msm_bigint(&g1, &scalars), expected_g1);
        assert_eq!(G2Projective::msm_bigint(&g2, &scalars), expected_g2);
    }
}
