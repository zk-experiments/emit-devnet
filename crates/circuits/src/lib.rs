//! The combining registry of the devnet: this repository's layers, frozen here as
//! `emit-devnet@0.2.0` (bytecode bundled): the emit layer's transfer app (`emit/transfer_holder`,
//! bound to a registered holder, every note 0 or at least 1/3 of the native coin) and the identity cache
//! (`identity_cache/register`, `identity_cache/member`); eid-circuits' identity layer
//! (`eid/dsc`, `eid/sod`, `eid/document`) and zk-encryption's channel layer (`channel/session`,
//! `channel/envelope`, `channel/note_envelope`) wrapped from their crates, and the pipelines
//! declared in `circuits/manifest.toml`:
//!
//! - `circuits::pipelines::{identity_register, member_transfer}`: `ROOT`, `PIPELINE`, a typed
//!   `Outputs`, `fold(&pool)` and `verify(&proof)`;
//! - `circuits::{DEPLOYMENT, DEPLOYMENT_ROOT, FAMILIES}`;
//! - [`pins`]: `pins.toml` (every version, catalog and root the devnet trusts) and its startup check;
//! - [`setup`]: the artifacts a fold draws from, loaded from the registries' CDNs and checked.

pub mod pins;
pub mod setup;

pub use noir_zk_backend::chonk::FoldedProof;
pub use noir_zk_core::{Error, Field};

/// Generated from the manifest (see the crate docs).
#[allow(missing_docs, clippy::all)]
pub mod circuits {
    include!(concat!(env!("OUT_DIR"), "/circuits.rs"));
}

use circuits::pipelines::{identity_register, member_transfer};

/// The pipelines a chain accepts, by root.
pub fn pipeline(root: &[u8; 32]) -> Option<&'static noir_zk_core::PipelineEntry> {
    [&*identity_register::PIPELINE, &*member_transfer::PIPELINE]
        .into_iter()
        .find(|p| p.root == *root)
}

/// Verifies a folded proof of the pipeline with root `pipeline_root` under noir-zk's hiding key,
/// the deployment root and the pipeline's root and length: returns every public field
/// (`deployment_root`, `pipeline_root`, `length`, then the slots in the pipeline's order).
pub fn verify(pipeline_root: &[u8; 32], proof: &[u8]) -> Result<Vec<Field>, Error> {
    let p = pipeline(pipeline_root)
        .ok_or_else(|| Error::Proof("not a pipeline of this deployment".into()))?;
    let proof = FoldedProof::from_bytes(proof)?;
    noir_zk_backend::pipeline::verify(
        &proof,
        p,
        circuits::DEPLOYMENT.root_field(),
        noir_zk_backend::pipeline::hiding_vk(),
    )
}

/// This crate's emit layer as artifacts (bytecode bundled, checked against its pin).
pub fn emit_artifacts() -> noir_zk_backend::Frozen<noir_zk_backend::BundledStore> {
    noir_zk_backend::Frozen::layered(
        circuits::REGISTRY,
        circuits::FAMILIES,
        noir_zk_backend::BundledStore(circuits::ASSETS),
    )
}

/// `0x`-prefixed big-endian hex of 32 bytes.
pub fn hex32(b: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipelines_are_as_declared() {
        let names = |p: &noir_zk_core::PipelineEntry| {
            p.positions
                .iter()
                .map(|x| format!("{}/{}", x.family.library, x.family.family))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(&identity_register::PIPELINE),
            [
                "eid-circuits/dsc",
                "eid-circuits/sod",
                "eid-circuits/document",
                "emit-devnet/register"
            ]
        );
        assert_eq!(identity_register::PIPELINE.slots.len(), 6);
        assert_eq!(
            names(&member_transfer::PIPELINE),
            [
                "emit-devnet/member",
                "zk-encryption/session",
                "zk-encryption/envelope",
                "emit-devnet/transfer_holder",
                "zk-encryption/note_envelope"
            ]
        );
        assert_eq!(member_transfer::PIPELINE.slots.len(), 31);
        assert_eq!(circuits::DEPLOYMENT.roots.len(), 2);
        assert!(pipeline(&member_transfer::ROOT).is_some());
        assert!(pipeline(&[0; 32]).is_none());
    }
}
