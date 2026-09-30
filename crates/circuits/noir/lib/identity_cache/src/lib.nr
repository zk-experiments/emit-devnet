//! The identity cache: prove the passport once, then prove membership.
//!
//! `register` follows eid's document step (it continues the step's DG1 PayloadCommitment) and
//! publishes one leaf of the pool's identity tree,
//! `L = H(IDENTITY, H(PK, sk), H(payload), expiry, r)`, with `expiry` no later than the passport's
//! own date of expiry, read from the MRZ the payload carries, and `r` a uniform random blinding
//! the wallet keeps: without it, anyone who knows the holder's shielded address and MRZ (a payee
//! who reads the MRZ from their envelopes) could recompute the leaf and find the registration. `identity_member` proves a leaf is
//! in the tree under a public root and still valid at the public date, leaves a fresh commitment
//! to the same payload for the DG1 envelope, and publishes the holder tag `H(HOLDER, sk, ctx)`
//! the transfer (`emit::transfer_holder`) is bound to. Specification: the repository's README.

mod tests;

use channel::payload::commit;
use eid_steps::document::{DG1_MAX, PAYLOAD_FIELDS, parse_dg1, plaintext};
use emit::{h, holder_tag, merkle_root, PK, TREE_DEPTH};

/// "emit-v2/identity/v2" as a big-endian integer (v2: the blinded leaf).
pub global IDENTITY: Field = 0x656d69742d76322f6964656e746974792f7632;

/// `register`'s record: `[payload_commitment, leaf, expiry]`.
pub global REGISTER_FIELDS: u32 = 3;
/// `identity_member`'s record: `[payload_commitment, identity_root, date, holder_tag]`.
pub global MEMBER_FIELDS: u32 = 4;

/// The identity tree's leaf: `H(IDENTITY, H(PK, sk), H(payload), expiry, blinding)`.
pub fn leaf(sk: Field, payload: [Field; PAYLOAD_FIELDS], expiry: u64, blinding: Field) -> Field {
    h([IDENTITY, h([PK, sk]), h(payload), expiry as Field, blinding])
}

/// Registers the holder of `sk` with the document whose DG1 (`dg1`, zero-padded) the previous
/// step committed to under `payload_salt`, until `expiry` (unix seconds, at most the passport's
/// date of expiry), blinded by `blinding` (uniform random, kept by the holder).
pub fn register(
    payload_salt: Field,
    dg1: [u8; DG1_MAX],
    sk: Field,
    expiry: u64,
    blinding: Field,
) -> [Field; REGISTER_FIELDS] {
    let d = parse_dg1(dg1);
    assert(expiry <= d.expires, "the registration outlives the passport");
    let payload = plaintext(dg1, d.len);
    [commit(payload_salt, payload), leaf(sk, payload, expiry, blinding), expiry as Field]
}

/// Proves the leaf of (`sk`, `payload`, `expiry`, `blinding`) is at `index` in the identity tree under
/// `identity_root` and valid at `date`; commits to the payload afresh under `payload_salt` and
/// tags the holder in the transfer context `ctx`.
pub fn member(
    identity_root: Field,
    date: u64,
    sk: Field,
    payload: [Field; PAYLOAD_FIELDS],
    payload_salt: Field,
    expiry: u64,
    blinding: Field,
    index: Field,
    path: [Field; TREE_DEPTH],
    ctx: Field,
) -> [Field; MEMBER_FIELDS] {
    assert(
        merkle_root(leaf(sk, payload, expiry, blinding), index, path) == identity_root,
        "not a registered identity",
    );
    assert(date <= expiry, "the registration has expired");
    [commit(payload_salt, payload), identity_root, date as Field, holder_tag(sk, ctx)]
}
