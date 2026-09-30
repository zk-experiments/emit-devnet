//! Membership in the identity cache as a Chonk app: returns `[payload_commitment, identity_root,
//! date, holder_tag]` (`identity_cache::member`); the payload commitment is the link the DG1
//! envelope continues.
use emit::TREE_DEPTH;
use identity_cache::{member, MEMBER_FIELDS};

fn main(
    identity_root: Field,
    date: u64,
    sk: Field,
    payload: [Field; 6],
    payload_salt: Field,
    expiry: u64,
    blinding: Field,
    index: Field,
    path: [Field; TREE_DEPTH],
    ctx: Field,
) -> return_data [Field; MEMBER_FIELDS] {
    member(identity_root, date, sk, payload, payload_salt, expiry, blinding, index, path, ctx)
}
