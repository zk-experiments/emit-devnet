use std::collections::{BTreeMap, BTreeSet};

use acir::{
    FieldElement,
    circuit::{
        Circuit, Opcode,
        brillig::{BrilligInputs, BrilligOutputs},
        opcodes::{BlackBoxFuncCall, FunctionInput, MemOpKind},
    },
    native_types::{Expression, Witness, WitnessMap},
};
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};

use crate::gadgets;

pub struct Step<'a> {
    pub circuit: &'a Circuit<FieldElement>,
    pub witness: Option<&'a WitnessMap<FieldElement>>,
    pub outputs: Vec<Witness>,
}

/// All application ACIR relations, their private links, and the public statement.
/// Mapping is part of the setup relation, not a verifier-side precheck.
pub struct Relation<'a> {
    pub steps: Vec<Step<'a>>,
    pub links: &'a [crate::fixture::Link],
    pub public_outputs: &'a [[usize; 2]],
    pub public: Option<&'a [Fr]>,
}

impl ConstraintSynthesizer<Fr> for Relation<'_> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let public = allocate_public(cs.clone(), self.public_outputs.len(), self.public)?;
        let records = self.steps.iter()
            .map(|step| synthesize_step(cs.clone(), step))
            .collect::<Result<Vec<_>, _>>()?;
        bind_records(&records, self.links, self.public_outputs, &public)
    }
}

pub(crate) fn allocate_public(
    cs: ConstraintSystemRef<Fr>,
    count: usize,
    values: Option<&[Fr]>,
) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
    if values.is_some_and(|values| values.len() != count) {
        return Err(SynthesisError::ArityMismatch);
    }
    (0..count).map(|i| FpVar::new_input(cs.clone(), || {
        values.map(|values| values[i]).ok_or(SynthesisError::AssignmentMissing)
    })).collect()
}

pub(crate) fn bind_records(
    records: &[Vec<FpVar<Fr>>],
    links: &[crate::fixture::Link],
    public_outputs: &[[usize; 2]],
    public: &[FpVar<Fr>],
) -> Result<(), SynthesisError> {
    if public.len() != public_outputs.len() {
        return Err(SynthesisError::ArityMismatch);
    }
    let output = |[app, index]: [usize; 2]| {
        records.get(app).and_then(|record| record.get(index))
            .ok_or(SynthesisError::ArityMismatch)
    };
    for link in links {
        output(link.from)?.enforce_equal(output(link.to)?)?;
    }
    for (mapping, input) in public_outputs.iter().zip(public) {
        output(*mapping)?.enforce_equal(input)?;
    }
    Ok(())
}

fn field(value: FieldElement) -> Fr {
    value.into_repr()
}

fn expression_witnesses(expression: &Expression<FieldElement>, witnesses: &mut BTreeSet<Witness>) {
    for (_, lhs, rhs) in &expression.mul_terms {
        witnesses.insert(*lhs);
        witnesses.insert(*rhs);
    }
    witnesses.extend(
        expression
            .linear_combinations
            .iter()
            .map(|(_, witness)| *witness),
    );
}

fn bound_input(
    bounds: &mut BTreeMap<Witness, usize>,
    input: &FunctionInput<FieldElement>,
    width: u32,
) -> Result<(), SynthesisError> {
    if width > Fr::MODULUS_BIT_SIZE {
        return Err(SynthesisError::Unsatisfiable);
    }
    if let FunctionInput::Witness(witness) = input {
        bounds
            .entry(*witness)
            .and_modify(|bound| *bound = (*bound).min(width as usize))
            .or_insert(width as usize);
    }
    Ok(())
}

/// Synthesizes one ACIR relation with private witnesses only. The caller must bind
/// the returned variables to the surrounding relation (Registration does so).
/// Brillig calls are witness-generation hints, never additional constraints.
pub fn synthesize_step(
    cs: ConstraintSystemRef<Fr>,
    step: &Step<'_>,
) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
    let mut witnesses = step.circuit.private_parameters.clone();
    witnesses.extend(&step.circuit.public_parameters.0);
    witnesses.extend(&step.circuit.return_values.0);
    witnesses.extend(&step.outputs);
    let mut constants = BTreeMap::new();
    let mut bounds = BTreeMap::new();
    let mutable_blocks: BTreeSet<_> = step
        .circuit
        .opcodes
        .iter()
        .filter_map(|op| match op {
            Opcode::MemoryOp { block_id, op } if op.operation == MemOpKind::Write => {
                Some(block_id.as_u32())
            }
            _ => None,
        })
        .collect();
    for opcode in &step.circuit.opcodes {
        match opcode {
            Opcode::AssertZero(expression) => {
                expression_witnesses(expression, &mut witnesses);
                // Only ACIR equations, not the assignment, justify specialization.
                // Keep every original equation and constrain the private variable
                // before substituting the proven constant elsewhere.
                if expression.mul_terms.is_empty() && expression.linear_combinations.len() == 1 {
                    let (coefficient, witness) = expression.linear_combinations[0];
                    if let Some(inverse) = field(coefficient).inverse() {
                        constants
                            .entry(witness)
                            .or_insert(-field(expression.q_c) * inverse);
                    }
                }
            }
            Opcode::BlackBoxFuncCall(call) => {
                match call {
                    BlackBoxFuncCall::RANGE { input, num_bits } => {
                        bound_input(&mut bounds, input, *num_bits)?;
                    }
                    BlackBoxFuncCall::AND {
                        lhs, rhs, num_bits, ..
                    }
                    | BlackBoxFuncCall::XOR {
                        lhs, rhs, num_bits, ..
                    } => {
                        bound_input(&mut bounds, lhs, *num_bits)?;
                        bound_input(&mut bounds, rhs, *num_bits)?;
                    }
                    BlackBoxFuncCall::Poseidon2Permutation { inputs, outputs } => {
                        if inputs.len() != 4 || outputs.len() != 4 {
                            return Err(SynthesisError::ArityMismatch);
                        }
                    }
                    BlackBoxFuncCall::Sha256Compression {
                        inputs,
                        hash_values,
                        ..
                    } => {
                        for input in inputs.iter().chain(hash_values.iter()) {
                            bound_input(&mut bounds, input, 32)?;
                        }
                    }
                    _ => return Err(SynthesisError::PredicateNotFound),
                }
                witnesses.extend(call.get_input_witnesses());
                witnesses.extend(call.get_outputs_vec());
            }
            Opcode::MemoryInit { init, .. } => witnesses.extend(init),
            Opcode::MemoryOp { op, .. } => {
                witnesses.insert(op.index);
                witnesses.insert(op.value);
            }
            Opcode::BrilligCall {
                inputs,
                outputs,
                predicate,
                ..
            } => {
                expression_witnesses(predicate, &mut witnesses);
                for input in inputs {
                    match input {
                        BrilligInputs::Single(expression) => {
                            expression_witnesses(expression, &mut witnesses)
                        }
                        BrilligInputs::Array(expressions) => {
                            for expression in expressions {
                                expression_witnesses(expression, &mut witnesses);
                            }
                        }
                        BrilligInputs::MemoryArray(_) => {}
                    }
                }
                for output in outputs {
                    match output {
                        BrilligOutputs::Simple(witness) => {
                            witnesses.insert(*witness);
                        }
                        BrilligOutputs::Array(array) => witnesses.extend(array),
                    }
                }
            }
            _ => return Err(SynthesisError::PredicateNotFound),
        }
    }
    let mut variables = BTreeMap::new();
    // The sorted set comes exclusively from ACIR, including output and hint
    // witnesses. Missing assignments are permitted by arkworks in Setup mode.
    for witness in witnesses {
        let variable = FpVar::new_witness(cs.clone(), || {
            step.witness
                .and_then(|map| map.get(&witness))
                .copied()
                .map(field)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        if let Some(value) = constants.get(&witness) {
            variable.enforce_equal(&FpVar::Constant(*value))?;
        }
        variables.insert(witness, variable);
    }
    let mut adapter = Adapter {
        cs,
        variables,
        constants,
        bounds,
        bits: BTreeMap::new(),
        selectors: BTreeMap::new(),
    };
    let mut memory = BTreeMap::<u32, Vec<FpVar<Fr>>>::new();
    let mut lookup_tables = BTreeMap::new();
    for opcode in &step.circuit.opcodes {
        match opcode {
            Opcode::AssertZero(expression) => adapter.assert_zero(expression)?,
            Opcode::BlackBoxFuncCall(call) => adapter.black_box(call)?,
            Opcode::MemoryInit { block_id, init, .. } => {
                if memory.contains_key(&block_id.as_u32()) {
                    return Err(SynthesisError::Unsatisfiable);
                }
                if init.len().is_power_of_two() && !mutable_blocks.contains(&block_id.as_u32()) {
                    if let Some(values) = init
                        .iter()
                        .map(|w| adapter.constants.get(w).copied())
                        .collect::<Option<Vec<_>>>()
                    {
                        lookup_tables.insert(block_id.as_u32(), ConstantLookup::new(values));
                    }
                }
                memory.insert(
                    block_id.as_u32(),
                    init.iter().map(|w| adapter.variable(*w)).collect(),
                );
            }
            Opcode::MemoryOp { block_id, op } => {
                if let Some(table) = lookup_tables.get(&block_id.as_u32()) {
                    let bits =
                        adapter.input_bits(&FunctionInput::Witness(op.index), table.width)?;
                    table
                        .evaluate(&bits)
                        .enforce_equal(&adapter.variable(op.value))?;
                    continue;
                }
                let block = memory
                    .get_mut(&block_id.as_u32())
                    .ok_or(SynthesisError::Unsatisfiable)?;
                let value = adapter.variable(op.value);
                if let Some(index) = adapter.constants.get(&op.index) {
                    let limbs = index.into_bigint();
                    let limbs = limbs.as_ref();
                    if limbs[1..].iter().any(|limb| *limb != 0) {
                        return Err(SynthesisError::Unsatisfiable);
                    }
                    let index =
                        usize::try_from(limbs[0]).map_err(|_| SynthesisError::Unsatisfiable)?;
                    let cell = block.get_mut(index).ok_or(SynthesisError::Unsatisfiable)?;
                    match op.operation {
                        MemOpKind::Read => cell.enforce_equal(&value)?,
                        MemOpKind::Write => *cell = value,
                    }
                } else {
                    let selectors = adapter.memory_selectors(op.index, block.len())?;
                    match op.operation {
                        MemOpKind::Read => {
                            let mut selected = FpVar::zero();
                            for (selector, cell) in selectors.iter().zip(block.iter()) {
                                selected += FpVar::from(selector.clone()) * cell;
                            }
                            selected.enforce_equal(&value)?;
                        }
                        MemOpKind::Write => {
                            for (selector, cell) in selectors.iter().zip(block.iter_mut()) {
                                *cell = selector.select(&value, cell)?;
                            }
                        }
                    }
                }
            }
            Opcode::BrilligCall { .. } => {}
            _ => return Err(SynthesisError::PredicateNotFound),
        }
    }
    Ok(step
        .outputs
        .iter()
        .map(|witness| adapter.variable(*witness))
        .collect())
}

/// The unique multilinear polynomial of a fixed ROM on Boolean address bits.
/// A Möbius transform derives it from *every* pinned table entry, not from a
/// known table name or the witness. SHA-384/512's base-four tables become sparse
/// linear/quadratic relations instead of thousands of selectors per read.
struct ConstantLookup {
    width: usize,
    constant: Fr,
    products: Vec<(usize, usize)>,
    terms: Vec<(Fr, usize)>,
}

impl ConstantLookup {
    fn new(mut values: Vec<Fr>) -> Self {
        let width = values.len().trailing_zeros() as usize;
        for bit in 0..width {
            for mask in 0..values.len() {
                if mask & (1 << bit) != 0 {
                    let lower = values[mask ^ (1 << bit)];
                    values[mask] -= lower;
                }
            }
        }
        let mut table = Self {
            width,
            constant: values[0],
            products: vec![],
            terms: vec![],
        };
        let mut slots = vec![None; values.len()];
        for bit in 0..width {
            slots[1 << bit] = Some(bit);
        }
        fn slot(
            mask: usize,
            width: usize,
            slots: &mut [Option<usize>],
            products: &mut Vec<(usize, usize)>,
        ) -> usize {
            if let Some(index) = slots[mask] {
                return index;
            }
            let bit = mask.trailing_zeros() as usize;
            let rest = slot(mask ^ (1 << bit), width, slots, products);
            let index = width + products.len();
            products.push((bit, rest));
            slots[mask] = Some(index);
            index
        }
        for (mask, coefficient) in values.into_iter().enumerate().skip(1) {
            if coefficient != Fr::ZERO {
                let index = slot(mask, width, &mut slots, &mut table.products);
                table.terms.push((coefficient, index));
            }
        }
        table
    }

    fn evaluate(&self, bits: &[Boolean<Fr>]) -> FpVar<Fr> {
        let mut values = Vec::with_capacity(self.width + self.products.len());
        values.extend(bits.iter().cloned().map(FpVar::from));
        for &(left, right) in &self.products {
            values.push(&values[left] * &values[right]);
        }
        let mut output = FpVar::Constant(self.constant);
        for &(coefficient, index) in &self.terms {
            output += &values[index] * coefficient;
        }
        output
    }
}

struct Adapter {
    cs: ConstraintSystemRef<Fr>,
    variables: BTreeMap<Witness, FpVar<Fr>>,
    constants: BTreeMap<Witness, Fr>,
    bounds: BTreeMap<Witness, usize>,
    bits: BTreeMap<Witness, Vec<Boolean<Fr>>>,
    selectors: BTreeMap<(Witness, usize), Vec<Boolean<Fr>>>,
}

impl Adapter {
    fn variable(&self, witness: Witness) -> FpVar<Fr> {
        self.constants
            .get(&witness)
            .map(|value| FpVar::Constant(*value))
            .unwrap_or_else(|| self.variables[&witness].clone())
    }

    fn input(&self, input: &FunctionInput<FieldElement>) -> FpVar<Fr> {
        match input {
            FunctionInput::Constant(value) => FpVar::Constant(field(*value)),
            FunctionInput::Witness(witness) => self.variable(*witness),
        }
    }

    fn add_term(lc: &mut LinearCombination<Fr>, variable: &FpVar<Fr>, coefficient: Fr) {
        if coefficient == Fr::ZERO {
            return;
        }
        match variable {
            FpVar::Constant(value) => lc.0.push((coefficient * value, Variable::One)),
            FpVar::Var(value) => lc.0.push((coefficient, value.variable)),
        }
    }

    fn assert_zero(&self, expression: &Expression<FieldElement>) -> Result<(), SynthesisError> {
        let mut linear = LinearCombination::zero();
        Self::add_term(
            &mut linear,
            &FpVar::Constant(field(expression.q_c)),
            Fr::ONE,
        );
        for (coefficient, witness) in &expression.linear_combinations {
            Self::add_term(&mut linear, &self.variable(*witness), field(*coefficient));
        }
        if let [(coefficient, lhs, rhs)] = expression.mul_terms.as_slice() {
            let mut a = LinearCombination::zero();
            let mut b = LinearCombination::zero();
            Self::add_term(&mut a, &self.variable(*lhs), field(*coefficient));
            Self::add_term(&mut b, &self.variable(*rhs), Fr::ONE);
            self.cs.enforce_r1cs_constraint(|| a, || b, || -linear)
        } else {
            for (coefficient, lhs, rhs) in &expression.mul_terms {
                let coefficient = field(*coefficient);
                if coefficient != Fr::ZERO {
                    let product = self.variable(*lhs) * self.variable(*rhs);
                    Self::add_term(&mut linear, &product, coefficient);
                }
            }
            self.cs.enforce_r1cs_constraint(
                || linear,
                || LinearCombination::from(Variable::One),
                LinearCombination::zero,
            )
        }
    }

    fn input_bits(
        &mut self,
        input: &FunctionInput<FieldElement>,
        width: usize,
    ) -> Result<Vec<Boolean<Fr>>, SynthesisError> {
        let target = match input {
            FunctionInput::Witness(witness) => self
                .bounds
                .get(witness)
                .copied()
                .unwrap_or(width)
                .min(width),
            FunctionInput::Constant(_) => width,
        };
        let mut bits = match input {
            FunctionInput::Witness(witness) if self.bits.contains_key(witness) => {
                self.bits[witness].clone()
            }
            _ => {
                let variable = self.input(input);
                if target == Fr::MODULUS_BIT_SIZE as usize {
                    // Unlike a field equality alone, this enforces canonicality.
                    variable.to_bits_le()?
                } else {
                    variable.to_bits_le_with_top_bits_zero(target)?.0
                }
            }
        };
        if bits.len() > target {
            for bit in &bits[target..] {
                bit.enforce_equal(&Boolean::FALSE)?;
            }
            bits.truncate(target);
        }
        if let FunctionInput::Witness(witness) = input {
            self.bits.insert(*witness, bits.clone());
        }
        bits.resize(width, Boolean::FALSE);
        Ok(bits)
    }

    fn bind_bits(&mut self, output: Witness, bits: Vec<Boolean<Fr>>) -> Result<(), SynthesisError> {
        // The rc.5 solver reduces full-width bitwise results into the field.
        // Do not require the *result* bit string to be canonical: XOR of two
        // canonical 254-bit inputs may be >= p. Inputs remain canonical.
        let mut power = Fr::ONE;
        let mut result = FpVar::zero();
        for bit in &bits {
            result += FpVar::from(bit.clone()) * power;
            power.double_in_place();
        }
        result.enforce_equal(&self.variable(output))?;
        if bits.len() < Fr::MODULUS_BIT_SIZE as usize && !self.bits.contains_key(&output) {
            self.bits.insert(output, bits);
        }
        Ok(())
    }

    fn memory_selectors(
        &mut self,
        index: Witness,
        length: usize,
    ) -> Result<Vec<Boolean<Fr>>, SynthesisError> {
        if let Some(selectors) = self.selectors.get(&(index, length)) {
            return Ok(selectors.clone());
        }
        let index_var = self.variable(index);
        let selectors = (0..length)
            .map(|i| index_var.is_eq(&FpVar::Constant(Fr::from(i as u64))))
            .collect::<Result<Vec<_>, _>>()?;
        let mut sum = FpVar::zero();
        for selector in &selectors {
            sum += FpVar::from(selector.clone());
        }
        // Enforces membership even for writes and empty arrays, rather than
        // silently returning zero or leaving memory unchanged out of range.
        sum.enforce_equal(&FpVar::one())?;
        self.selectors.insert((index, length), selectors.clone());
        Ok(selectors)
    }

    fn black_box(&mut self, call: &BlackBoxFuncCall<FieldElement>) -> Result<(), SynthesisError> {
        match call {
            BlackBoxFuncCall::RANGE { input, num_bits } => {
                self.input_bits(input, *num_bits as usize)?;
            }
            BlackBoxFuncCall::AND {
                lhs,
                rhs,
                num_bits,
                output,
            }
            | BlackBoxFuncCall::XOR {
                lhs,
                rhs,
                num_bits,
                output,
            } => {
                let lhs = self.input_bits(lhs, *num_bits as usize)?;
                let rhs = self.input_bits(rhs, *num_bits as usize)?;
                let is_and = matches!(call, BlackBoxFuncCall::AND { .. });
                let bits = lhs
                    .iter()
                    .zip(&rhs)
                    .map(|(lhs, rhs)| if is_and { lhs & rhs } else { lhs ^ rhs })
                    .collect();
                self.bind_bits(*output, bits)?;
            }
            BlackBoxFuncCall::Poseidon2Permutation { inputs, outputs } => {
                let mut state = std::array::from_fn(|i| self.input(&inputs[i]));
                gadgets::poseidon2(&mut state)?;
                for (value, output) in state.iter().zip(outputs) {
                    value.enforce_equal(&self.variable(*output))?;
                }
            }
            BlackBoxFuncCall::Sha256Compression {
                inputs,
                hash_values,
                outputs,
            } => {
                let input = inputs
                    .iter()
                    .map(|input| {
                        self.input_bits(input, 32)
                            .map(|bits| UInt32::from_bits_le(&bits))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let state = hash_values
                    .iter()
                    .map(|input| {
                        self.input_bits(input, 32)
                            .map(|bits| UInt32::from_bits_le(&bits))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let result = gadgets::sha256_compress(
                    input
                        .try_into()
                        .map_err(|_| SynthesisError::ArityMismatch)?,
                    state
                        .try_into()
                        .map_err(|_| SynthesisError::ArityMismatch)?,
                )?;
                for (word, output) in result.iter().zip(outputs.iter()) {
                    self.bind_bits(*output, word.to_bits_le()?)?;
                }
            }
            _ => return Err(SynthesisError::PredicateNotFound),
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "circuit_tests.rs"]
mod tests;
