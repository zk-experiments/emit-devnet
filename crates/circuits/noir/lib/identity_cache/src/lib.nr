//! The identity cache: prove the passport once, then prove membership.
//!
//! `register` follows eid's document step (it continues the step's DG1 PayloadCommitment) and
//! publishes one leaf of the pool's identity tree,
//! `L = H(IDENTITY, H(PK, sk), H(payload), expiry)`, with `expiry` no later than the passport's
//! own date of expiry, read from the MRZ the payload carries. `identity_member` proves a leaf is
//! in the tree under a public root and still valid at the public date, leaves a fresh commitment
//! to the same payload for the DG1 envelope, and publishes the holder tag `H(HOLDER, sk, ctx)`
//! the transfer (`emit::transfer_holder`) is bound to. Specification: the repository's README.

mod tests;

use channel::payload::commit;
use eid_steps::document::{DG1_MAX, PAYLOAD_FIELDS, parse_dg1, plaintext};
use emit::{h, holder_tag, merkle_root, PK, TREE_DEPTH};

/// "emit-v2/identity" as a big-endian integer.
pub global IDENTITY: Field = 0x656d69742d76322f6964656e74697479;

/// `register`'s record: `[payload_commitment, leaf, expiry]`.
pub global REGISTER_FIELDS: u32 = 3;
/// `identity_member`'s record: `[payload_commitment, identity_root, date, holder_tag]`.
pub global MEMBER_FIELDS: u32 = 4;

/// The identity tree's leaf: `H(IDENTITY, H(PK, sk), H(payload), expiry)`.
pub fn leaf(sk: Field, payload: [Field; PAYLOAD_FIELDS], expiry: u64) -> Field {
    h([IDENTITY, h([PK, sk]), h(payload), expiry as Field])
}

/// Registers the holder of `sk` with the document whose DG1 (`dg1`, zero-padded) the previous
/// step committed to under `payload_salt`, until `expiry` (unix seconds, at most the passport's
/// date of expiry).
pub fn register(
    payload_salt: Field,
    dg1: [u8; DG1_MAX],
    sk: Field,
    expiry: u64,
) -> [Field; REGISTER_FIELDS] {
    let d = parse_dg1(dg1);
    assert(expiry <= d.expires, "the registration outlives the passport");
    let payload = plaintext(dg1, d.len);
    [commit(payload_salt, payload), leaf(sk, payload, expiry), expiry as Field]
}

/// Proves the leaf of (`sk`, `payload`, `expiry`) is at `index` in the identity tree under
/// `identity_root` and valid at `date`; commits to the payload afresh under `payload_salt` and
/// tags the holder in the transfer context `ctx`.
pub fn member(
    identity_root: Field,
    date: u64,
    sk: Field,
    payload: [Field; PAYLOAD_FIELDS],
    payload_salt: Field,
    expiry: u64,
    index: Field,
    path: [Field; TREE_DEPTH],
    ctx: Field,
) -> [Field; MEMBER_FIELDS] {
    assert(
        merkle_root(leaf(sk, payload, expiry), index, path) == identity_root,
        "not a registered identity",
    );
    assert(date <= expiry, "the registration has expired");
    [commit(payload_salt, payload), identity_root, date as Field, holder_tag(sk, ctx)]
}
