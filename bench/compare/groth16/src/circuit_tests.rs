use super::*;
use acir::{
    AcirField,
    circuit::opcodes::{BlockId, BlockType, MemOp},
};
use ark_ff::BigInteger;
use ark_relations::gr1cs::{ConstraintSystem, SynthesisMode};

fn assignment(values: &[u64]) -> WitnessMap<FieldElement> {
    values
        .iter()
        .enumerate()
        .map(|(i, value)| (Witness(i as u32 + 1), FieldElement::from(*value)))
        .collect::<BTreeMap<_, _>>()
        .into()
}

fn circuit(opcodes: Vec<Opcode<FieldElement>>) -> Circuit<FieldElement> {
    Circuit {
        opcodes,
        ..Circuit::default()
    }
}

fn synthesize(
    circuit: &Circuit<FieldElement>,
    witness: &WitnessMap<FieldElement>,
) -> Result<ConstraintSystemRef<Fr>, SynthesisError> {
    let cs = ConstraintSystem::new_ref();
    synthesize_step(
        cs.clone(),
        &Step {
            circuit,
            witness: Some(witness),
            outputs: vec![],
        },
    )?;
    Ok(cs)
}

fn satisfied(circuit: &Circuit<FieldElement>, witness: &WitnessMap<FieldElement>) -> bool {
    match synthesize(circuit, witness) {
        Ok(cs) => cs.is_satisfied().unwrap(),
        Err(SynthesisError::Unsatisfiable) => false,
        Err(error) => panic!("unexpected synthesis failure: {error}"),
    }
}

fn range(witness: u32, num_bits: u32) -> Opcode<FieldElement> {
    Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
        input: FunctionInput::Witness(Witness(witness)),
        num_bits,
    })
}

#[test]
fn arithmetic_tampering_fails_for_single_and_multiple_products() {
    let mut product = Expression::default();
    product
        .mul_terms
        .push((FieldElement::one(), Witness(1), Witness(2)));
    product
        .linear_combinations
        .push((-FieldElement::one(), Witness(3)));
    let single = circuit(vec![Opcode::AssertZero(product.clone())]);
    assert!(satisfied(&single, &assignment(&[3, 4, 12])));
    assert!(!satisfied(&single, &assignment(&[3, 4, 13])));
    product
        .mul_terms
        .push((FieldElement::from(2u64), Witness(1), Witness(1)));
    product.q_c = FieldElement::from(5u64);
    let multiple = circuit(vec![Opcode::AssertZero(product)]);
    assert!(satisfied(&multiple, &assignment(&[3, 4, 35])));
    assert!(!satisfied(&multiple, &assignment(&[3, 4, 36])));
}

#[test]
fn range_bounds_are_exact_cached_and_full_width_is_canonical() {
    let small = circuit(vec![range(1, 8), range(1, 4), range(1, 8)]);
    let cs = synthesize(&small, &assignment(&[15])).unwrap();
    assert!(cs.is_satisfied().unwrap());
    assert!(!satisfied(&small, &assignment(&[16])));
    assert!(satisfied(&circuit(vec![range(1, 0)]), &assignment(&[0])));
    assert!(!satisfied(&circuit(vec![range(1, 0)]), &assignment(&[1])));
    let full = circuit(vec![range(1, 254)]);
    let mut maximal = WitnessMap::new();
    maximal.insert(Witness(1), -FieldElement::one());
    assert!(satisfied(&full, &maximal));
    assert!(!satisfied(&circuit(vec![range(1, 253)]), &maximal));

    // Attempt the field alias 0 == p in the *bits*, not merely an overflowing
    // field assignment (which would already have been reduced before synthesis).
    let canonical_cs = ConstraintSystem::new_ref();
    let zero = FpVar::new_witness(canonical_cs.clone(), || Ok(Fr::ZERO)).unwrap();
    let mut adapter = Adapter {
        cs: canonical_cs.clone(),
        variables: BTreeMap::from([(Witness(1), zero)]),
        constants: BTreeMap::new(),
        bounds: BTreeMap::new(),
        bits: BTreeMap::new(),
        selectors: BTreeMap::new(),
    };
    let bits = adapter
        .input_bits(&FunctionInput::Witness(Witness(1)), 254)
        .unwrap();
    canonical_cs.finalize(); // evaluate mutations through inlined LCs, not cached assignments
    let modulus = Fr::MODULUS.to_bits_le();
    for (bit, value) in bits.iter().zip(modulus) {
        let Boolean::Var(bit) = bit else {
            panic!("expected allocated bit")
        };
        canonical_cs
            .borrow_mut()
            .unwrap()
            .assignments
            .witness_assignment[bit.variable().index().unwrap()] = Fr::from(value as u64);
    }
    assert!(!canonical_cs.is_satisfied().unwrap());
}

#[test]
fn logical_outputs_are_bound_and_full_width_xor_reduces() {
    let logical = circuit(vec![
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::AND {
            lhs: FunctionInput::Witness(Witness(1)),
            rhs: FunctionInput::Witness(Witness(2)),
            num_bits: 4,
            output: Witness(3),
        }),
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::XOR {
            lhs: FunctionInput::Witness(Witness(1)),
            rhs: FunctionInput::Witness(Witness(2)),
            num_bits: 4,
            output: Witness(4),
        }),
    ]);
    assert!(satisfied(&logical, &assignment(&[12, 10, 8, 6])));
    assert!(!satisfied(&logical, &assignment(&[12, 10, 9, 6])));
    assert!(!satisfied(&logical, &assignment(&[12, 10, 8, 7])));
    assert!(!satisfied(&logical, &assignment(&[28, 10, 8, 6])));

    let lhs = -Fr::ONE;
    let rhs = Fr::from(2u64); // (p - 1) XOR 2 = p + 1, reduced to 1
    let bytes = lhs
        .into_bigint()
        .to_bytes_le()
        .into_iter()
        .zip(rhs.into_bigint().to_bytes_le())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<_>>();
    let expected = Fr::from_le_bytes_mod_order(&bytes);
    assert_eq!(expected, Fr::ONE);
    let mut map = WitnessMap::new();
    for (i, value) in [lhs, rhs, expected].into_iter().enumerate() {
        map.insert(
            Witness(i as u32 + 1),
            FieldElement::from_be_bytes_reduce(&value.into_bigint().to_bytes_be()),
        );
    }
    let full = circuit(vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::XOR {
        lhs: FunctionInput::Witness(Witness(1)),
        rhs: FunctionInput::Witness(Witness(2)),
        num_bits: 254,
        output: Witness(3),
    })]);
    assert!(satisfied(&full, &map));
    map.insert(Witness(3), FieldElement::zero());
    assert!(!satisfied(&full, &map));
}

#[test]
fn variable_memory_reads_writes_and_bounds_are_constrained() {
    let block_id = BlockId::new(0);
    let memory = circuit(vec![
        Opcode::MemoryInit {
            block_id,
            init: vec![Witness(1), Witness(2)],
            block_type: BlockType::Memory,
        },
        Opcode::MemoryOp {
            block_id,
            op: MemOp::read_at_mem_index(Witness(3), Witness(4)),
        },
        Opcode::MemoryOp {
            block_id,
            op: MemOp::write_to_mem_index(Witness(5), Witness(6)),
        },
        Opcode::MemoryOp {
            block_id,
            op: MemOp::read_at_mem_index(Witness(3), Witness(7)),
        },
    ]);
    assert!(satisfied(&memory, &assignment(&[11, 22, 1, 22, 1, 33, 33])));
    assert!(satisfied(&memory, &assignment(&[11, 22, 0, 11, 1, 33, 11])));
    for invalid in [
        [11, 22, 1, 11, 1, 33, 33], // wrong initial read
        [11, 22, 1, 22, 1, 33, 22], // stale read after write
        [11, 22, 2, 0, 1, 33, 0],   // out-of-range read
        [11, 22, 1, 22, 2, 33, 22], // out-of-range write must not be a no-op
    ] {
        assert!(!satisfied(&memory, &assignment(&invalid)));
    }
    let mut negative_index = assignment(&[11, 22, 1, 22, 1, 33, 33]);
    negative_index.insert(Witness(5), -FieldElement::one());
    assert!(!satisfied(&memory, &negative_index));
}

#[test]
fn constant_memory_specialization_still_constrains_the_index() {
    let block_id = BlockId::new(0);
    let mut fixed = Expression::default();
    fixed
        .linear_combinations
        .push((FieldElement::from(2u64), Witness(3)));
    fixed.q_c = -FieldElement::from(2u64);
    let memory = circuit(vec![
        Opcode::MemoryInit {
            block_id,
            init: vec![Witness(1), Witness(2)],
            block_type: BlockType::ReturnData,
        },
        Opcode::MemoryOp {
            block_id,
            op: MemOp::read_at_mem_index(Witness(3), Witness(4)),
        },
        // Constant evidence need not precede the memory operation.
        Opcode::AssertZero(fixed),
    ]);
    let cs = synthesize(&memory, &assignment(&[11, 22, 1, 22])).unwrap();
    assert!(cs.is_satisfied().unwrap());
    assert!(!satisfied(&memory, &assignment(&[11, 22, 0, 22])));
    assert!(!satisfied(&memory, &assignment(&[11, 22, 1, 11])));
}

#[test]
fn constant_rom_polynomial_preserves_entries_bounds_and_writes() {
    let block_id = BlockId::new(0);
    let values = [9u64, 4, 27, 1, 33, 18, 6, 12];
    let mut opcodes = Vec::new();
    for (i, value) in values.iter().enumerate() {
        let mut fixed = Expression::default();
        fixed
            .linear_combinations
            .push((FieldElement::one(), Witness(i as u32 + 1)));
        fixed.q_c = -FieldElement::from(*value);
        opcodes.push(Opcode::AssertZero(fixed));
    }
    opcodes.push(Opcode::MemoryInit {
        block_id,
        init: (1..=8).map(Witness).collect(),
        block_type: BlockType::Memory,
    });
    let mut readonly = opcodes.clone();
    readonly.push(Opcode::MemoryOp {
        block_id,
        op: MemOp::read_at_mem_index(Witness(9), Witness(10)),
    });
    let readonly = circuit(readonly);
    for (index, expected) in values.iter().enumerate() {
        let mut input = values.to_vec();
        input.extend([index as u64, *expected]);
        assert!(satisfied(&readonly, &assignment(&input)));
        input[9] += 1;
        assert!(!satisfied(&readonly, &assignment(&input)));
    }
    let mut input = values.to_vec();
    input.extend([8, 9]);
    assert!(!satisfied(&readonly, &assignment(&input)));
    input[8] = 0;
    input[0] += 1;
    assert!(!satisfied(&readonly, &assignment(&input)));

    opcodes.push(Opcode::MemoryOp {
        block_id,
        op: MemOp::write_to_mem_index(Witness(9), Witness(10)),
    });
    opcodes.push(Opcode::MemoryOp {
        block_id,
        op: MemOp::read_at_mem_index(Witness(9), Witness(11)),
    });
    let writable = circuit(opcodes);
    let mut input = values.to_vec();
    input.extend([3, 77, 77]);
    assert!(satisfied(&writable, &assignment(&input)));
    input[10] = values[3];
    assert!(!satisfied(&writable, &assignment(&input)));
}

#[test]
fn sparse_sha_lookup_does_not_expand_into_a_selector_per_entry() {
    // The base-four bit encoding used by the pinned SHA-512 implementation.
    let values: Vec<_> = (0..1024)
        .map(|i| {
            Fr::from(
                (0..10)
                    .map(|bit| ((i >> bit) & 1u64) << (2 * bit))
                    .sum::<u64>(),
            )
        })
        .collect();
    let table = ConstantLookup::new(values.clone());
    for index in [0usize, 1, 511, 1023] {
        let cs = ConstraintSystem::new_ref();
        let address = FpVar::new_witness(cs.clone(), || Ok(Fr::from(index as u64))).unwrap();
        let bits = address
            .to_bits_le_with_top_bits_zero(table.width)
            .unwrap()
            .0;
        table
            .evaluate(&bits)
            .enforce_equal(&FpVar::Constant(values[index]))
            .unwrap();
        assert!(cs.is_satisfied().unwrap());
        // A complexity bound, not an exact gate count: scanning each entry would
        // expand passport SHA-384/512 into tens of millions of table-cell checks.
        assert!(cs.num_constraints() < 100);
    }
}

#[test]
fn poseidon_and_sha_outputs_cannot_be_changed() {
    let inputs = [0u64, 1, 2, 3].map(FieldElement::from);
    let outputs = bn254_blackbox_solver::poseidon2_permutation(&inputs).unwrap();
    let poseidon = circuit(vec![Opcode::BlackBoxFuncCall(
        BlackBoxFuncCall::Poseidon2Permutation {
            inputs: (1..=4)
                .map(|i| FunctionInput::Witness(Witness(i)))
                .collect(),
            outputs: (5..=8).map(Witness).collect(),
        },
    )]);
    let mut map = assignment(&[0, 1, 2, 3]);
    for (i, value) in outputs.into_iter().enumerate() {
        map.insert(Witness(i as u32 + 5), value);
    }
    assert!(satisfied(&poseidon, &map));
    map.insert(Witness(8), map[&Witness(8)] + FieldElement::one());
    assert!(!satisfied(&poseidon, &map));

    let iv = [
        0x6a09e667u64,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let digest = [
        0xe3b0c442u64,
        0x98fc1c14,
        0x9afbf4c8,
        0x996fb924,
        0x27ae41e4,
        0x649b934c,
        0xa495991b,
        0x7852b855,
    ];
    let sha = circuit(vec![Opcode::BlackBoxFuncCall(
        BlackBoxFuncCall::Sha256Compression {
            inputs: Box::new(std::array::from_fn(|i| {
                if i == 0 {
                    FunctionInput::Witness(Witness(1))
                } else {
                    FunctionInput::Constant(FieldElement::zero())
                }
            })),
            hash_values: Box::new(std::array::from_fn(|i| {
                if i == 0 {
                    FunctionInput::Witness(Witness(2))
                } else {
                    FunctionInput::Constant(FieldElement::from(iv[i]))
                }
            })),
            outputs: Box::new(std::array::from_fn(|i| Witness(i as u32 + 3))),
        },
    )]);
    let mut map = assignment(&[0x80000000, iv[0]]);
    for (i, value) in digest.into_iter().enumerate() {
        map.insert(Witness(i as u32 + 3), FieldElement::from(value));
    }
    assert!(satisfied(&sha, &map));
    map.insert(Witness(3), FieldElement::from(digest[0] + 1));
    assert!(!satisfied(&sha, &map));
}

fn registration<'a>(
    circuits: &'a [Circuit<FieldElement>; 4],
    maps: Option<&'a [WitnessMap<FieldElement>; 4]>,
    public: Option<&'a [Fr; 6]>,
) -> Relation<'a> {
    Relation {
        steps: (0..4).map(|i| Step {
            circuit: &circuits[i],
            witness: maps.map(|maps| &maps[i]),
            outputs: (1..=[2, 2, 5, 3][i]).map(Witness).collect(),
        }).collect(),
        links: &[
            crate::fixture::Link { from: [0, 1], to: [1, 0] },
            crate::fixture::Link { from: [1, 1], to: [2, 0] },
            crate::fixture::Link { from: [2, 1], to: [3, 0] },
        ],
        public_outputs: &[[0, 0], [2, 2], [2, 3], [2, 4], [3, 1], [3, 2]],
        public: public.map(|values| values.as_slice()),
    }
}

#[test]
fn all_private_links_and_six_public_outputs_are_enforced() {
    let circuits = [2, 2, 5, 3].map(|length| circuit((1..=length).map(|i| range(i, 64)).collect()));
    let maps = [
        assignment(&[10, 20]),
        assignment(&[20, 30]),
        assignment(&[30, 40, 50, 60, 70]),
        assignment(&[40, 80, 90]),
    ];
    let public = [10u64, 50, 60, 70, 80, 90].map(Fr::from);
    let good = ConstraintSystem::new_ref();
    registration(&circuits, Some(&maps), Some(&public))
        .generate_constraints(good.clone())
        .unwrap();
    assert!(good.is_satisfied().unwrap());
    assert_eq!(good.num_instance_variables(), 7); // implicit one + exactly six
    for stage in 1..4 {
        let mut bad = maps.clone();
        let changed = bad[stage][&Witness(1)] + FieldElement::one();
        bad[stage].insert(Witness(1), changed);
        let cs = ConstraintSystem::new_ref();
        registration(&circuits, Some(&bad), Some(&public))
            .generate_constraints(cs.clone())
            .unwrap();
        assert!(!cs.is_satisfied().unwrap(), "link into stage {stage}");
    }
    for i in 0..6 {
        let mut bad_public = public;
        bad_public[i] += Fr::ONE;
        let cs = ConstraintSystem::new_ref();
        registration(&circuits, Some(&maps), Some(&bad_public))
            .generate_constraints(cs.clone())
            .unwrap();
        assert!(!cs.is_satisfied().unwrap(), "public output {i}");
    }
    let setup = ConstraintSystem::new_ref();
    setup.set_mode(SynthesisMode::Setup);
    registration(&circuits, None, None)
        .generate_constraints(setup.clone())
        .unwrap();
    assert_eq!(setup.num_instance_variables(), 7);
    assert_eq!(setup.num_witness_variables(), good.num_witness_variables());
    setup.finalize();
    good.finalize();
    assert_eq!(setup.to_matrices().unwrap(), good.to_matrices().unwrap());
}

#[test]
fn missing_assignments_and_unsupported_constraints_are_errors() {
    let range = circuit(vec![range(1, 8)]);
    let cs = ConstraintSystem::new_ref();
    assert!(matches!(
        synthesize_step(
            cs,
            &Step {
                circuit: &range,
                witness: None,
                outputs: vec![]
            }
        ),
        Err(SynthesisError::AssignmentMissing)
    ));
    let unsupported = circuit(vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Blake3 {
        inputs: vec![],
        outputs: Box::new([Witness(1); 32]),
    })]);
    let cs = ConstraintSystem::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    assert!(matches!(
        synthesize_step(
            cs,
            &Step {
                circuit: &unsupported,
                witness: None,
                outputs: vec![]
            }
        ),
        Err(SynthesisError::PredicateNotFound)
    ));
}
