//! Generates the combining registry from `circuits/manifest.toml`: this crate's own emit layer
//! (frozen by `noir-zk freeze`, bytecode bundled), the identity and channel layers wrapped from
//! their crates' generated registries, the pipelines and every root.

use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_default());
    println!("cargo:rerun-if-changed=circuits");
    println!("cargo:rerun-if-changed=resources");
    println!("cargo:rerun-if-changed=assets");
    let options = noir_zk_codegen::Options {
        bundle: vec!["*".into()],
        sources: vec![
            (
                "eid-circuits".into(),
                noir_zk_codegen::wrapped(
                    eid_circuits::circuits::LIBRARY,
                    eid_circuits::circuits::REGISTRY,
                    eid_circuits::circuits::FAMILIES,
                ),
            ),
            (
                "zk-encryption".into(),
                noir_zk_codegen::wrapped(
                    zk_encryption_circuits::circuits::LIBRARY,
                    zk_encryption_circuits::circuits::REGISTRY,
                    zk_encryption_circuits::circuits::FAMILIES,
                ),
            ),
        ],
    };
    std::fs::write(
        out.join("circuits.rs"),
        noir_zk_codegen::generate_registry_with(&dir, &options),
    )
    .unwrap_or_else(|e| panic!("circuits.rs: {e}"));
}
