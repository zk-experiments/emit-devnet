//! What a fold draws from, loaded from where each layer publishes it and checked against the
//! pins compiled into its crate:
//!
//! - eid's DSC and SOD steps: the circuit packs of the pinned catalog (`pins.toml` `eid.catalog`,
//!   SHA-256 pinned); each pack's SHA-256 is checked against the catalog, then every unpacked
//!   file against eid's registry (`frozen::verify_dir`);
//! - eid's document steps: from a pinned catalog's pack when one carries them, else compiled
//!   from eid's Noir source at the pinned revision with the pinned nargo (v0.8.0's packs are not
//!   published yet); `Frozen` refuses bytecode that doesn't hash to its pin either way;
//! - the channel layer: bundled in `zk-encryption-circuits` (its catalog is checked by the pins);
//! - the emit layer: bundled in this crate; the kernels: bundled in noir-zk.

use crate::pins::{Pins, cache_dir, fetch, fetch_pinned};
use noir_zk_backend::{ArtifactStore, BundledStore, Frozen};
use noir_zk_core::Error;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

fn err(e: impl std::fmt::Display) -> Error {
    Error::Artifact(e.to_string())
}

/// eid's bytecode: the unpacked packs, then the document steps compiled from source.
pub struct EidStore {
    pub packs: PathBuf,
    pub target: PathBuf,
}

impl ArtifactStore for EidStore {
    fn fetch(&self, asset: &str) -> Result<Vec<u8>, Error> {
        if let Ok(b) = std::fs::read(self.packs.join(asset)) {
            return Ok(b);
        }
        let label = asset.split('@').next().unwrap_or(asset);
        let path = self.target.join(format!("{label}.json"));
        let json = std::fs::read_to_string(&path)
            .map_err(|e| err(format!("{asset}: not in the packs, {}: {e}", path.display())))?;
        let v: serde_json::Value = serde_json::from_str(&json).map_err(err)?;
        v["bytecode"]
            .as_str()
            .map(|b| b.as_bytes().to_vec())
            .ok_or_else(|| err(format!("{label}: no bytecode")))
    }
}

/// Every layer's artifacts; `merged()` is what `fold` takes.
pub struct Pool {
    eid: Frozen<EidStore>,
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

/// The pinned nargo (`$NARGO`, else `~/.toolchains/noir-1.0.0-rc.3/bin/nargo`).
pub fn nargo() -> String {
    std::env::var("NARGO").unwrap_or_else(|_| {
        format!(
            "{}/.toolchains/noir-{}/bin/nargo",
            std::env::var("HOME").unwrap_or_default(),
            crate::circuits::NOIR_VERSION
        )
    })
}

fn run(cmd: &mut Command) -> Result<(), Error> {
    let out = cmd.output().map_err(|e| err(format!("{cmd:?}: {e}")))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(err(format!("{cmd:?}: {}", String::from_utf8_lossy(&out.stderr))))
    }
}

/// Loads the pool for folds using the eid circuits `labels` (DSC, SOD and document steps),
/// downloading and compiling what isn't cached. `log` gets a line per network or compile step.
pub fn pool(pins: &Pins, labels: &BTreeSet<String>, log: &dyn Fn(String)) -> Result<Pool, Error> {
    let e = &pins.eid;
    let catalog: serde_json::Value = serde_json::from_slice(
        &fetch_pinned(&e.catalog, &e.catalog_sha256).map_err(err)?,
    )
    .map_err(err)?;
    let version = catalog["version"].as_str().unwrap_or("unknown");
    let packs = cache_dir().join("eid-packs").join(version);
    std::fs::create_dir_all(&packs).map_err(err)?;
    let mut compile = vec![];
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
            None => compile.push(l.clone()),
        }
    }
    for name in &wanted {
        let marker = packs.join(format!(".{name}.ok"));
        if marker.exists() {
            continue;
        }
        let p = &catalog["packs"][name];
        let (file, sha) = (
            p["file"].as_str().ok_or_else(|| err(format!("pack {name}: no file")))?,
            p["sha256"].as_str().unwrap_or_default(),
        );
        let url = format!("{}/{file}", e.packs);
        log(format!("downloading eid pack {name} ({} MB) from {url}", p["bytes"].as_u64().unwrap_or(0) / 1_000_000));
        let bytes = fetch(&url).map_err(err)?;
        if hex::encode(Sha256::digest(&bytes)) != sha {
            return Err(err(format!("{file}: SHA-256 differs from the catalog")));
        }
        noir_zk_backend::pack::unpack(bytes.as_slice(), &packs)?;
        std::fs::write(&marker, sha).map_err(err)?;
    }
    // Every unpacked .b64 and .vk hashes to its pin in eid's registry.
    noir_zk_backend::frozen::verify_dir(eid_circuits::circuits::REGISTRY, &packs)?;

    let src = cache_dir().join(format!("eid-src-{}", e.rev));
    let target = src.join("target");
    let missing: Vec<_> = compile
        .iter()
        .filter(|l| !target.join(format!("{l}.json")).exists())
        .collect();
    if !missing.is_empty() {
        if !src.join("Nargo.toml").exists() {
            log(format!("fetching eid-circuits {} (Noir source) from {}", e.rev, e.source));
            std::fs::create_dir_all(&src).map_err(err)?;
            let git = |args: &[&str]| run(Command::new("git").args(args).current_dir(&src));
            git(&["init", "-q"])?;
            git(&["fetch", "-q", "--depth", "1", &e.source, &e.rev])?;
            git(&["checkout", "-q", "FETCH_HEAD"])?;
        }
        for l in missing {
            log(format!("compiling eid {l} from source (nargo {})", crate::circuits::NOIR_VERSION));
            run(Command::new(nargo())
                .args(["compile", "--silence-warnings", "--package", l])
                .current_dir(&src))?;
        }
    }
    Ok(Pool {
        eid: eid_circuits::artifacts(EidStore { packs, target }),
        channel: zk_encryption_circuits::artifacts(),
        emit: crate::emit_artifacts(),
    })
}
