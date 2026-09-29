//! `pins.toml`: every version, catalog and root the devnet trusts, in one file, compiled into
//! the node and the wallet and checked at startup ([`Pins::check`]): the catalogs are fetched
//! from their CDNs and must hash to their pins and agree with the layers compiled in; the
//! deployment and pipeline roots the codegen computed must equal the pinned ones.

use crate::circuits::{self, pipelines};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// The repository's `pins.toml`.
pub const PINS_TOML: &str = include_str!("../../../pins.toml");

#[derive(Clone, Debug, Deserialize)]
pub struct Pins {
    #[serde(rename = "noir-zk")]
    pub noir_zk: NoirZk,
    pub emit: Emit,
    #[serde(rename = "zk-encryption")]
    pub zk_encryption: ZkEncryption,
    pub eid: Eid,
    pub csca: Csca,
    pub deployment: Deployment,
}

#[derive(Clone, Debug, Deserialize)]
pub struct NoirZk {
    pub version: String,
    pub kernels_family_root: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Emit {
    pub library: String,
    pub transfer_family_root: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ZkEncryption {
    pub library: String,
    pub catalog: String,
    pub catalog_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Eid {
    pub library: String,
    /// The git revision whose Noir source the document steps are compiled from while no
    /// published catalog carries them.
    pub rev: String,
    pub source: String,
    pub packs: String,
    pub catalog: String,
    pub catalog_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Csca {
    pub tag: String,
    pub root: String,
    pub registry: String,
    pub registry_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Deployment {
    pub root: String,
    pub identity_transfer: PipelinePin,
    pub transfer_only: PipelinePin,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PipelinePin {
    pub root: String,
    pub length: usize,
}

fn check(what: &str, ok: bool, report: &mut Vec<String>) -> Result<(), String> {
    if ok {
        report.push(format!("ok  {what}"));
        Ok(())
    } else {
        Err(format!("pin check failed: {what}"))
    }
}

/// `$EMIT_DEVNET_CACHE` or `~/.cache/emit-devnet`.
pub fn cache_dir() -> PathBuf {
    std::env::var_os("EMIT_DEVNET_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".cache/emit-devnet")
        })
}

/// GET `url` (up to 512 MB).
pub fn fetch(url: &str) -> Result<Vec<u8>, String> {
    let mut resp = ureq::get(url).call().map_err(|e| format!("{url}: {e}"))?;
    resp.body_mut()
        .with_config()
        .limit(512 << 20)
        .read_to_vec()
        .map_err(|e| format!("{url}: {e}"))
}

/// `url`'s bytes if they hash to `sha256`: from the cache when present, else fetched and cached.
pub fn fetch_pinned(url: &str, sha256: &str) -> Result<Vec<u8>, String> {
    let path = cache_dir().join("pinned").join(format!(
        "{}-{sha256}",
        url.rsplit('/').next().unwrap_or("asset")
    ));
    if let Ok(b) = std::fs::read(&path)
        && hex::encode(Sha256::digest(&b)) == sha256
    {
        return Ok(b);
    }
    let b = fetch(url)?;
    let got = hex::encode(Sha256::digest(&b));
    if got != sha256 {
        return Err(format!("{url}: SHA-256 {got}, pinned {sha256}"));
    }
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&path, &b);
    Ok(b)
}

fn json(b: &[u8], what: &str) -> Result<serde_json::Value, String> {
    serde_json::from_slice(b).map_err(|e| format!("{what}: {e}"))
}

fn family(library: &str, family: &str) -> Option<&'static noir_zk_core::FamilyEntry> {
    circuits::FAMILIES
        .iter()
        .find(|f| f.id.library == library && f.id.family == family)
}

impl Pins {
    /// The compiled-in `pins.toml`.
    pub fn embedded() -> Self {
        toml::from_str(PINS_TOML).expect("pins.toml")
    }

    /// Checks the pins: the local ones against the compiled-in layers and codegen, the remote
    /// ones by fetching each catalog and registry and comparing hashes and contents (skipped
    /// with `offline`). Returns a line per check.
    pub fn check(&self, offline: bool) -> Result<Vec<String>, String> {
        let mut r = vec![];
        let lib = |l: noir_zk_core::Library| format!("{}@{}", l.name, l.version);

        // noir-zk: the kernels' family is the last leaf of every pipeline root.
        let kernels = crate::hex32(&noir_zk_backend::kernels::FAMILY.root);
        check(
            &format!(
                "noir-zk {} kernels family root {kernels}",
                self.noir_zk.version
            ),
            kernels == self.noir_zk.kernels_family_root
                && noir_zk_backend::kernels::FAMILY.version == self.noir_zk.version,
            &mut r,
        )?;

        // The emit layer (this crate).
        let transfer = family("emit-devnet", "transfer").ok_or("no emit/transfer family")?;
        check(
            &format!("emit layer {} transfer family root", self.emit.library),
            lib(circuits::LIBRARY) == self.emit.library
                && crate::hex32(&transfer.root) == self.emit.transfer_family_root,
            &mut r,
        )?;

        // The layers compiled in are the pinned versions.
        check(
            &format!("channel layer {}", self.zk_encryption.library),
            lib(zk_encryption_circuits::circuits::LIBRARY) == self.zk_encryption.library,
            &mut r,
        )?;
        check(
            &format!("identity layer {} (rev {})", self.eid.library, self.eid.rev),
            lib(eid_circuits::circuits::LIBRARY) == self.eid.library,
            &mut r,
        )?;

        // The deployment the codegen computed.
        check(
            &format!("deployment root {}", self.deployment.root),
            crate::hex32(&circuits::DEPLOYMENT_ROOT) == self.deployment.root,
            &mut r,
        )?;
        for (name, pin, root, len) in [
            (
                "identity_transfer",
                &self.deployment.identity_transfer,
                pipelines::identity_transfer::ROOT,
                pipelines::identity_transfer::PIPELINE.len(),
            ),
            (
                "transfer_only",
                &self.deployment.transfer_only,
                pipelines::transfer_only::ROOT,
                pipelines::transfer_only::PIPELINE.len(),
            ),
        ] {
            check(
                &format!("pipeline {name} root {} length {len}", pin.root),
                crate::hex32(&root) == pin.root && len == pin.length,
                &mut r,
            )?;
        }
        if offline {
            r.push("--  remote catalogs and registry skipped (offline)".into());
            return Ok(r);
        }

        // zk-encryption's published catalog: its families (library, version, members) are the
        // compiled-in ones. Its `kernels` entry names the noir-zk it was released against; the
        // kernels folded here are noir-zk's own, pinned above.
        let z = &self.zk_encryption;
        let cat = json(
            &fetch_pinned(&z.catalog, &z.catalog_sha256)?,
            "channel catalog",
        )?;
        let mut same = format!(
            "{}@{}",
            cat["library"].as_str().unwrap_or(""),
            cat["version"].as_str().unwrap_or("")
        ) == z.library;
        for f in cat["families"].as_array().into_iter().flatten() {
            let id = f["id"].as_str().unwrap_or("");
            let name = id.rsplit('/').next().unwrap_or("");
            same &= family("zk-encryption", name)
                .is_some_and(|e| Some(crate::hex32(&e.root).as_str()) == f["root"].as_str());
        }
        check(
            &format!(
                "channel catalog {} (sha256 {}): families (released against noir-zk {})",
                z.catalog,
                &z.catalog_sha256[..12],
                cat["kernels"]["version"].as_str().unwrap_or("?")
            ),
            same,
            &mut r,
        )?;

        // eid's published catalog: every DSC and SOD circuit it packs is in the compiled-in
        // registry (whose pins the unpacked bytecode is then checked against).
        let e = &self.eid;
        let cat = json(&fetch_pinned(&e.catalog, &e.catalog_sha256)?, "eid catalog")?;
        let known = |l: &str| {
            eid_circuits::circuits::REGISTRY
                .iter()
                .any(|x| x.label == l)
        };
        let mut steps = 0;
        let mut same = true;
        for p in cat["packs"]
            .as_object()
            .into_iter()
            .flat_map(|m| m.values())
        {
            for l in p["circuits"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|l| l.as_str())
            {
                if l.starts_with("dsc_") || l.starts_with("sod_") {
                    steps += 1;
                    same &= known(l);
                }
            }
        }
        check(
            &format!(
                "eid catalog {} (sha256 {}): {steps} DSC/SOD steps in {}",
                e.catalog,
                &e.catalog_sha256[..12],
                e.library
            ),
            same && steps > 0,
            &mut r,
        )?;

        // The published CSCA registry release.
        let c = &self.csca;
        let reg = json(
            &fetch_pinned(&c.registry, &c.registry_sha256)?,
            "csca registry",
        )?;
        check(
            &format!("csca registry {} root {}", c.tag, c.root),
            reg["commitment"]["root"].as_str() == Some(c.root.as_str()),
            &mut r,
        )?;
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn local_pins_hold() {
        let r = super::Pins::embedded().check(true).expect("pins");
        assert!(r.len() >= 7, "{r:?}");
    }
}
