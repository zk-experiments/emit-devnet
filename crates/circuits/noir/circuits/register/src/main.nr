//! The identity cache's registration as a Chonk app, after eid's document step: continues the
//! step's DG1 PayloadCommitment and returns `[payload_commitment, leaf, expiry]`
//! (`identity_cache::register`).
use eid_steps::document::DG1_MAX;
use identity_cache::{register, REGISTER_FIELDS};

fn main(
    payload_salt: Field,
    dg1: [u8; DG1_MAX],
    sk: Field,
    expiry: u64,
) -> return_data [Field; REGISTER_FIELDS] {
    register(payload_salt, dg1, sk, expiry)
}
