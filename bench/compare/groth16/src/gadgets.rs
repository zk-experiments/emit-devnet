//! ACIR-compatible BN254 Poseidon2 permutation and raw SHA-256 compression.
//!
//! Poseidon2 arithmetic adapted from outbe-circuits' groth16-tribute experiment;
//! constants and their MIT attribution are vendored in poseidon2_constants.rs.
//! SHA-256 compression adapted from ark-crypto-primitives 0.6.0,
//! src/crh/sha256/constraints.rs (itself adapted from nanpuyue/sha256,
//! bf6656b7dc72e76bb617445a8865f906670e585b). No padding is added.
//
// The MIT License (MIT)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

use crate::poseidon2_constants::BN254_CONFIG;
use ark_bn254::Fr;
use ark_r1cs_std::{
    fields::{FieldVar, fp::FpVar},
    uint32::UInt32,
};
use ark_relations::gr1cs::SynthesisError;

fn fifth_power(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let square = x.square()?;
    Ok(square.square()? * x)
}

// Same external matrix as barretenberg and outbe-poseidon, expressed as linear
// combinations so mixing introduces no multiplication constraints.
fn external_layer(state: &mut [FpVar<Fr>; 4]) {
    let t0 = &state[0] + &state[1];
    let t1 = &state[2] + &state[3];
    let t2 = &state[1] + &state[1] + &t1;
    let t3 = &state[3] + &state[3] + &t0;
    let t4 = &t1 + &t1;
    let t4 = &t4 + &t4 + &t3;
    let t5 = &t0 + &t0;
    let t5 = &t5 + &t5 + &t2;
    *state = [&t3 + &t5, t5, &t2 + &t4, t4];
}

pub fn poseidon2(state: &mut [FpVar<Fr>; 4]) -> Result<(), SynthesisError> {
    let config = &BN254_CONFIG;
    external_layer(state);
    let half_full = config.rounds_f as usize / 2;
    let partial_end = half_full + config.rounds_p as usize;
    for round in 0..(config.rounds_f + config.rounds_p) as usize {
        if (half_full..partial_end).contains(&round) {
            state[0] += config.round_constant[round][0];
            state[0] = fifth_power(&state[0])?;
            let sum = &state[0] + &state[1] + &state[2] + &state[3];
            for (value, diagonal) in state.iter_mut().zip(config.internal_matrix_diagonal) {
                *value = &*value * diagonal + &sum;
            }
        } else {
            for (value, constant) in state.iter_mut().zip(config.round_constant[round]) {
                *value += constant;
                *value = fifth_power(value)?;
            }
            external_layer(state);
        }
    }
    Ok(())
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Compress one sixteen-word block with an arbitrary eight-word chaining state.
/// Words use the standard SHA-256 numerical (big-endian message word) convention.
pub fn sha256_compress(
    input: [UInt32<Fr>; 16],
    mut state: [UInt32<Fr>; 8],
) -> Result<[UInt32<Fr>; 8], SynthesisError> {
    let mut w: [UInt32<Fr>; 64] = core::array::from_fn(|_| UInt32::constant(0));
    for (word, input) in w.iter_mut().zip(input) {
        *word = input;
    }
    for i in 16..64 {
        let s0 = {
            let x1 = w[i - 15].rotate_right(7);
            let x2 = w[i - 15].rotate_right(18);
            let x3 = &w[i - 15] >> 3u8;
            x1 ^ &x2 ^ &x3
        };
        let s1 = {
            let x1 = w[i - 2].rotate_right(17);
            let x2 = w[i - 2].rotate_right(19);
            let x3 = &w[i - 2] >> 10u8;
            x1 ^ &x2 ^ &x3
        };
        w[i] = UInt32::wrapping_add_many(&[w[i - 16].clone(), s0, w[i - 7].clone(), s1])?;
    }

    let mut h = state.clone();
    for i in 0..64 {
        let ch = {
            let x1 = &h[4] & &h[5];
            let x2 = (!&h[4]) & &h[6];
            x1 ^ &x2
        };
        let ma = {
            let x1 = &h[0] & &h[1];
            let x2 = &h[0] & &h[2];
            let x3 = &h[1] & &h[2];
            x1 ^ &x2 ^ &x3
        };
        let s0 = {
            let x1 = h[0].rotate_right(2);
            let x2 = h[0].rotate_right(13);
            let x3 = h[0].rotate_right(22);
            x1 ^ &x2 ^ &x3
        };
        let s1 = {
            let x1 = h[4].rotate_right(6);
            let x2 = h[4].rotate_right(11);
            let x3 = h[4].rotate_right(25);
            x1 ^ &x2 ^ &x3
        };
        let t0 = UInt32::wrapping_add_many(&[
            h[7].clone(),
            s1,
            ch,
            UInt32::constant(K[i]),
            w[i].clone(),
        ])?;
        let t1 = s0.wrapping_add(&ma);

        h[7] = h[6].clone();
        h[6] = h[5].clone();
        h[5] = h[4].clone();
        h[4] = h[3].wrapping_add(&t0);
        h[3] = h[2].clone();
        h[2] = h[1].clone();
        h[1] = h[0].clone();
        h[0] = t0.wrapping_add(&t1);
    }

    for (s, hi) in state.iter_mut().zip(h.iter()) {
        *s = s.wrapping_add(hi);
    }

    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use acir::{AcirField, FieldElement};
    use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
    use ark_r1cs_std::{GR1CSVar, alloc::AllocVar, eq::EqGadget};
    use ark_relations::gr1cs::ConstraintSystem;

    #[test]
    fn poseidon_matches_pinned_native_and_rejects_tampering() {
        let cases = [
            [Fr::ZERO; 4],
            [
                Fr::from(1u64),
                Fr::from(2u64),
                Fr::from(3u64),
                Fr::from(4u64),
            ],
            [-Fr::ONE; 4],
            [-Fr::ONE, -Fr::from(2u64), Fr::from(1u128 << 100), Fr::ZERO],
        ];
        for input in cases {
            let native =
                input.map(|x| FieldElement::from_be_bytes_reduce(&x.into_bigint().to_bytes_be()));
            let expected = bn254_blackbox_solver::poseidon2_permutation(&native).unwrap();
            let cs = ConstraintSystem::<Fr>::new_ref();
            let mut actual = input.map(|x| FpVar::new_witness(cs.clone(), || Ok(x)).unwrap());
            poseidon2(&mut actual).unwrap();
            for (actual, expected) in actual.iter().zip(expected) {
                let expected = Fr::from_be_bytes_mod_order(&expected.to_be_bytes());
                assert_eq!(actual.value().unwrap(), expected);
                actual
                    .enforce_equal(&FpVar::new_input(cs.clone(), || Ok(expected)).unwrap())
                    .unwrap();
            }
            assert!(cs.is_satisfied().unwrap());
            let wrong = actual[0].value().unwrap() + Fr::ONE;
            actual[0].enforce_equal(&FpVar::Constant(wrong)).unwrap();
            assert!(!cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn sha256_matches_native_multiple_blocks_and_rejects_tampering() {
        let states = [
            [0u32; 8],
            [u32::MAX; 8],
            [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            core::array::from_fn(|i| (i as u32).wrapping_mul(0x12345679)),
        ];
        let blocks = [
            [0u32; 16],
            [u32::MAX; 16],
            core::array::from_fn(|i| (i as u32).wrapping_mul(0x9e3779b9)),
        ];
        for initial in states {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let mut native = initial;
            let mut actual = initial.map(|x| UInt32::new_witness(cs.clone(), || Ok(x)).unwrap());
            for block in blocks {
                let mut bytes = [0u8; 64];
                for (chunk, word) in bytes.chunks_exact_mut(4).zip(block) {
                    chunk.copy_from_slice(&word.to_be_bytes());
                }
                sha2::compress256(&mut native, &[bytes.into()]);
                actual = sha256_compress(
                    block.map(|x| UInt32::new_witness(cs.clone(), || Ok(x)).unwrap()),
                    actual,
                )
                .unwrap();
                for (actual, expected) in actual.iter().zip(native) {
                    assert_eq!(actual.value().unwrap(), expected);
                    actual
                        .enforce_equal(&UInt32::new_input(cs.clone(), || Ok(expected)).unwrap())
                        .unwrap();
                }
                assert!(cs.is_satisfied().unwrap());
            }
            actual[0]
                .enforce_equal(&UInt32::constant(native[0] ^ 1))
                .unwrap();
            assert!(!cs.is_satisfied().unwrap());
        }
    }
}
