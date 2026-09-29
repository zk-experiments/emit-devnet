//! What a fold draws from, loaded from where each layer publishes it and checked against the
//! pins compiled into its crate:
//!
//! - eid's DSC, SOD and document steps: the circuit packs of the pinned catalog (`pins.toml`
//!   `eid.catalog`, SHA-256 pinned); each pack's SHA-256 is checked against the catalog, then
//!   every unpacked file against eid's registry (`frozen::verify_dir`), and `Frozen` refuses
//!   bytecode that doesn't hash to its pin;
//! - the channel layer: bundled in `zk-encryption-circuits` (its catalog is checked by the pins);
//! - the emit layer: bundled in this crate; the kernels: bundled in noir-zk.

use crate::pins::{Pins, cache_dir, fetch, fetch_pinned};
use noir_zk_backend::{BundledStore, DirStore, Frozen};
use noir_zk_core::Error;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

fn err(e: impl std::fmt::Display) -> Error {
    Error::Artifact(e.to_string())
}

/// Every layer's artifacts; `merged()` is what `fold` takes.
pub struct Pool {
    eid: Frozen<DirStore>,
    channel: Frozen<BundledStore>,
    emit: Frozen<BundledStore>,
}

impl Pool {
    pub fn merged(&self) -> noir_zk_core::Merged<'_> {
        noir_zk_core::Merged::new(&[
            &self.emit,
            &self.channel,
            &noir_zk_backend::kernels::Kernels,
            &self.eid,
        ])
    }
}

/// Loads the pool for folds using the eid circuits `labels` (DSC, SOD and document steps),
/// downloading the packs that carry them if not cached. `log` gets a line per download.
pub fn pool(pins: &Pins, labels: &BTreeSet<String>, log: &dyn Fn(String)) -> Result<Pool, Error> {
    let e = &pins.eid;
    let catalog: serde_json::Value =
        serde_json::from_slice(&fetch_pinned(&e.catalog, &e.catalog_sha256).map_err(err)?)
            .map_err(err)?;
    let version = catalog["version"].as_str().unwrap_or("unknown");
    let packs = cache_dir().join("eid-packs").join(version);
    std::fs::create_dir_all(&packs).map_err(err)?;
    let mut wanted = BTreeSet::new();
    for l in labels {
        let pack = catalog["packs"].as_object().and_then(|m| {
            m.iter().find(|(_, p)| {
                p["circuits"]
                    .as_array()
                    .is_some_and(|c| c.iter().any(|x| x.as_str() == Some(l.as_str())))
            })
        });
        match pack {
            Some((name, _)) => {
                wanted.insert(name.clone());
            }
            None => return Err(err(format!("{l}: in no pack of eid's catalog {version}"))),
        }
    }
    for name in &wanted {
        let marker = packs.join(format!(".{name}.ok"));
        if marker.exists() {
            continue;
        }
        let p = &catalog["packs"][name];
        let (file, sha) = (
            p["file"]
                .as_str()
                .ok_or_else(|| err(format!("pack {name}: no file")))?,
            p["sha256"].as_str().unwrap_or_default(),
        );
        let url = format!("{}/{file}", e.packs);
        log(format!(
            "downloading eid pack {name} ({} MB) from {url}",
            p["bytes"].as_u64().unwrap_or(0) / 1_000_000
        ));
        let bytes = fetch(&url).map_err(err)?;
        if hex::encode(Sha256::digest(&bytes)) != sha {
            return Err(err(format!("{file}: SHA-256 differs from the catalog")));
        }
        noir_zk_backend::pack::unpack(bytes.as_slice(), &packs)?;
        std::fs::write(&marker, sha).map_err(err)?;
    }
    // Every unpacked .b64 and .vk hashes to its pin in eid's registry.
    noir_zk_backend::frozen::verify_dir(eid_circuits::circuits::REGISTRY, &packs)?;

    Ok(Pool {
        eid: eid_circuits::artifacts(DirStore(packs)),
        channel: zk_encryption_circuits::artifacts(),
        emit: crate::emit_artifacts(),
    })
}
