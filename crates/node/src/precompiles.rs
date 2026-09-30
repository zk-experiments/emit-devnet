//! The devnet's two precompiles.
//!
//! `ZK_VERIFY` (0x…0100): input `pipeline_root (32 bytes) ‖ proof` (the folded Chonk proof,
//! a whole number of 32-byte fields). Verifies the proof under noir-zk's hiding key, the
//! pinned deployment root and the pipeline's root and length (the pipeline must be one of the
//! deployment's), and returns every public field ABI-encoded as `uint256[]`
//! (`deployment_root, pipeline_root, length`, then the pipeline's slots in order). A proof that
//! doesn't verify reverts with the reason as bytes, after charging the gas.
//! Gas: `ZK_VERIFY_GAS` flat (verification cost doesn't depend on the pipeline) plus
//! `ZK_VERIFY_PER_WORD` per 32 bytes of input. The outcome is cached by the input's hash: a block
//! runs each transaction twice (building it, then validating it), and verifies each proof once.
//!
//! `POSEIDON2` (0x…0101): input `n ≥ 1` 32-byte big-endian BN254 field elements (each < p);
//! returns Noir's `Poseidon2::hash(inputs, n)` (the t = 4 sponge the circuits use, pso-poseidon's
//! `hash_noir`). Gas: `POSEIDON2_BASE + POSEIDON2_PER_PERM · ⌈n / 3⌉` (one permutation per rate
//! block).

use alloy_primitives::{B256, Bytes, address, keccak256};
use ark_ff::{BigInteger, PrimeField};
use reth_ethereum::evm::revm::precompile::{
    Precompile, PrecompileHalt, PrecompileId, PrecompileOutput, PrecompileResult, Precompiles,
};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use zk_encryption_circuits::wallet::Fr;
use zk_encryption_circuits::wallet::poseidon::Poseidon;

pub const ZK_VERIFY: alloy_primitives::Address =
    address!("0x0000000000000000000000000000000000000100");
pub const POSEIDON2: alloy_primitives::Address =
    address!("0x0000000000000000000000000000000000000101");

/// Flat gas of a verification: a Chonk verification takes 17-20 ms on an Apple M5 Max
/// (bb 7.0.0-nightly.20260927, measured by the wallet before each send), priced at 60 Mgas/s,
/// ecrecover's rate (3,000 gas for ~50 µs).
pub const ZK_VERIFY_GAS: u64 = 1_200_000;
/// Per 32-byte word of input (reading and decoding the proof).
pub const ZK_VERIFY_PER_WORD: u64 = 3;
/// Poseidon2: a call and one permutation per three inputs (~6 µs each natively).
pub const POSEIDON2_BASE: u64 = 60;
pub const POSEIDON2_PER_PERM: u64 = 360;

fn zk_verify(input: &[u8], gas_limit: u64, reservoir: u64) -> PrecompileResult {
    let gas = ZK_VERIFY_GAS + ZK_VERIFY_PER_WORD * input.len().div_ceil(32) as u64;
    if gas > gas_limit {
        return Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, reservoir));
    }
    let fail = |why: String| {
        Ok(PrecompileOutput::revert(
            gas,
            Bytes::from(why.into_bytes()),
            reservoir,
        ))
    };
    match verified(input) {
        Ok(out) => Ok(PrecompileOutput::new(gas, out, reservoir)),
        Err(why) => fail(why),
    }
}

/// Verification outcomes by input hash. The outcome is a function of the input alone, so a cached
/// one is the one a fresh verification would give.
const CACHE_ENTRIES: usize = 1024;

fn verified(input: &[u8]) -> Result<Bytes, String> {
    static CACHE: OnceLock<Mutex<HashMap<B256, Result<Bytes, String>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    let key = keccak256(input);
    if let Some(hit) = cache.lock().expect("cache").get(&key) {
        return hit.clone();
    }
    let out = verify(input);
    let mut c = cache.lock().expect("cache");
    // ponytail: cleared whole when full; an LRU if a node ever sees more proofs than this in flight.
    if c.len() >= CACHE_ENTRIES {
        c.clear();
    }
    c.insert(key, out.clone());
    out
}

fn verify(input: &[u8]) -> Result<Bytes, String> {
    let (root, proof) = input
        .split_first_chunk::<32>()
        .ok_or("ZK_VERIFY: input shorter than a pipeline root")?;
    let fields =
        emit_devnet_circuits::verify(root, proof).map_err(|e| format!("ZK_VERIFY: {e}"))?;
    let mut out = Vec::with_capacity(64 + 32 * fields.len());
    out.extend(word(32));
    out.extend(word(fields.len() as u64));
    for f in &fields {
        out.extend(be32(f));
    }
    Ok(out.into())
}

fn poseidon2(input: &[u8], gas_limit: u64, reservoir: u64) -> PrecompileResult {
    let n = input.len() / 32;
    let gas = POSEIDON2_BASE + POSEIDON2_PER_PERM * n.div_ceil(3) as u64;
    let halt = |h| Ok(PrecompileOutput::halt(h, reservoir));
    if gas > gas_limit {
        return halt(PrecompileHalt::OutOfGas);
    }
    if n == 0 || !input.len().is_multiple_of(32) {
        return halt(PrecompileHalt::other(
            "POSEIDON2: input is not n >= 1 words",
        ));
    }
    let mut fields = Vec::with_capacity(n);
    for w in input.chunks(32) {
        let f = Fr::from_be_bytes_mod_order(w);
        if be32(&f) != w {
            return halt(PrecompileHalt::other(
                "POSEIDON2: word is not a canonical field element",
            ));
        }
        fields.push(f);
    }
    Ok(PrecompileOutput::new(
        gas,
        be32(&Poseidon::hash(&fields)).to_vec().into(),
        reservoir,
    ))
}

fn word(x: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&x.to_be_bytes());
    w
}

fn be32(f: &Fr) -> [u8; 32] {
    let b = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    out
}

/// Prague's precompiles plus the two above.
pub fn prague() -> &'static Precompiles {
    static P: OnceLock<Precompiles> = OnceLock::new();
    P.get_or_init(|| {
        let mut p = Precompiles::prague().clone();
        p.extend([
            Precompile::new(PrecompileId::custom("zk_verify"), ZK_VERIFY, zk_verify),
            Precompile::new(PrecompileId::custom("poseidon2"), POSEIDON2, poseidon2),
        ]);
        p
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_ethereum::evm::revm::precompile::PrecompileStatus;

    #[test]
    fn poseidon2_matches_the_circuits_hash() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let input = [be32(&a), be32(&b)].concat();
        let out = poseidon2(&input, 1_000_000, 0).expect("hash");
        assert_eq!(out.bytes.as_ref(), be32(&Poseidon::hash(&[a, b])));
        assert_eq!(out.gas_used, POSEIDON2_BASE + POSEIDON2_PER_PERM);
        assert!(
            poseidon2(&[0xff; 32], 1_000_000, 0)
                .expect("halts")
                .status
                .is_halt(),
            "non-canonical"
        );
        assert!(
            poseidon2(&[], 1_000_000, 0)
                .expect("halts")
                .status
                .is_halt(),
            "empty"
        );
    }

    #[test]
    fn zk_verify_refuses_garbage() {
        let root = emit_devnet_circuits::circuits::pipelines::member_transfer::ROOT;
        let input = [root.as_slice(), &[0u8; 64]].concat();
        let out = zk_verify(&input, 10_000_000, 0).expect("runs");
        assert_eq!(out.status, PrecompileStatus::Revert);
        // Again, from the cache: the same outcome and gas.
        let again = zk_verify(&input, 10_000_000, 0).expect("runs");
        assert_eq!(
            (again.status, again.gas_used, again.bytes),
            (out.status, out.gas_used, out.bytes)
        );
        assert!(
            zk_verify(&[0u8; 96], 1, 0).expect("halts").status.is_halt(),
            "out of gas"
        );
    }
}
