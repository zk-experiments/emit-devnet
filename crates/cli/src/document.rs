//! The six synthetic passports (`fixtures/documents.json`, from the experiments repository: a
//! mock CSCA, the complete EF.SOD with its DSC, and DG1 each), the csca-registry of their CSCAs
//! the devnet accepts, and their eid witnesses (eid-prover v0.8.0).

use csca_registry::output::Registry;
use zk_encryption_circuits::wallet::Fr;
use zk_encryption_circuits::wallet::emit::Dg1;
use zk_encryption_circuits::wallet::poseidon::{FieldHex, Rng};
use zk_encryption_circuits::wallet::ratchet::Ratchet;

#[derive(Clone, Debug)]
pub struct Document {
    pub name: String,
    pub csca_der: Vec<u8>,
    pub ef_sod: Vec<u8>,
    pub dg1: Dg1,
}

/// The inputs of one document's apps for one transfer.
pub struct Witnesses {
    pub dsc: String,
    pub sod: String,
    pub document: String,
    /// The DG1 envelope app (channel/envelope).
    pub envelope: String,
    pub labels: [String; 3],
}

pub fn fixtures() -> Vec<Document> {
    let json: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/documents.json")).expect("documents.json");
    let hex = |v: &serde_json::Value| hex::decode(v.as_str().expect("hex")).expect("hex");
    json["documents"]
        .as_array()
        .expect("documents")
        .iter()
        .map(|d| Document {
            name: d["name"].as_str().expect("name").into(),
            csca_der: hex(&d["csca"]),
            ef_sod: hex(&d["ef_sod"]),
            dg1: Dg1(hex(&d["dg1"])),
        })
        .collect()
}

pub fn by_name(name: &str) -> eyre::Result<Document> {
    let all = fixtures();
    let names: Vec<_> = all.iter().map(|d| d.name.clone()).collect();
    all.into_iter()
        .find(|d| d.name == name)
        .ok_or_else(|| eyre::eyre!("no document {name}; the fixtures are {}", names.join(", ")))
}

/// The registry of the six mock CSCAs: what the DSC steps prove against and the pool accepts.
pub fn registry() -> eyre::Result<Registry> {
    let mut b = csca_registry::registry::Builder::default();
    for d in fixtures() {
        b.add_certificates(&format!("{}-csca.der", d.name), &d.csca_der);
    }
    b.finish().map_err(|e| eyre::eyre!("registry: {e}"))
}

pub fn registry_root(reg: &Registry) -> Fr {
    Fr::from_hex(&reg.commitment.root)
}

impl Document {
    /// The step inputs for one transfer (fresh salts): eid's DSC, SOD and document steps
    /// (scope 0, the DG1 salt), and the channel envelope app sealing DG1 under the chain key `s`
    /// in the transfer's context.
    pub fn witnesses(&self, reg: &Registry, date: u64, ctx: Fr, s: Fr) -> eyre::Result<Witnesses> {
        let dg1_salt = Rng::field();
        let w = eid_prover::witnesses(
            reg,
            &self.ef_sod,
            &self.dg1.0,
            &eid_prover::Params {
                dsc_salt: Rng::field().hex(),
                sod_salt: Rng::field().hex(),
                dg1_salt: dg1_salt.hex(),
                date: date as i64,
                scope: "0".into(),
            },
        )
        .map_err(|e| eyre::eyre!("{}: {e}", self.name))?;
        Ok(Witnesses {
            dsc: w.dsc,
            sod: w.sod,
            document: w.document,
            envelope: zk_encryption_circuits::envelope::inputs(
                Ratchet::key_payload(),
                &self.dg1.to_payload(),
                dg1_salt,
                ctx,
                s,
            ),
            labels: [w.selection.dsc, w.selection.sod, w.selection.document],
        })
    }

    /// The MRZ (DG1 without its 5-byte tag and length header).
    pub fn mrz(dg1: &Dg1) -> String {
        String::from_utf8_lossy(dg1.0.get(5..).unwrap_or_default()).into_owned()
    }
}
