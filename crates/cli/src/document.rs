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
    /// eid's DSC, SOD and document steps' inputs (fresh salts) at `date` in nullifier `scope`
    /// ("0" for none), and the salt of the document's DG1 commitment.
    pub fn eid(
        &self,
        reg: &Registry,
        date: u64,
        scope: &str,
    ) -> eyre::Result<(eid_prover::Witnesses, Fr)> {
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
                scope: scope.into(),
            },
        )
        .map_err(|e| eyre::eyre!("{}: {e}", self.name))?;
        Ok((w, dg1_salt))
    }

    /// The step inputs for one transfer: eid's steps (scope 0), and the channel envelope app
    /// sealing DG1 under the chain key `s` in the transfer's context.
    pub fn witnesses(&self, reg: &Registry, date: u64, ctx: Fr, s: Fr) -> eyre::Result<Witnesses> {
        let (w, dg1_salt) = self.eid(reg, date, "0")?;
        Ok(Witnesses {
            dsc: w.dsc,
            sod: w.sod,
            document: w.document,
            envelope: self.envelope(dg1_salt, ctx, s),
            labels: [w.selection.dsc, w.selection.sod, w.selection.document],
        })
    }

    /// The DG1 envelope app's inputs: DG1's payload, committed under `salt`, sealed under the
    /// chain key `s` in context `ctx`.
    pub fn envelope(&self, salt: Fr, ctx: Fr, s: Fr) -> String {
        zk_encryption_circuits::envelope::inputs(
            Ratchet::key_payload(),
            &self.dg1.to_payload(),
            salt,
            ctx,
            s,
        )
    }

    /// The passport's date of expiry (its last second, unix time).
    pub fn expires(&self) -> eyre::Result<u64> {
        let d = eid_prover::mrz::parse_dg1(&self.dg1.0).map_err(|e| eyre::eyre!("DG1: {e}"))?;
        Ok(d.expires as u64)
    }

    /// The MRZ (DG1 without its 5-byte tag and length header).
    pub fn mrz(dg1: &Dg1) -> String {
        String::from_utf8_lossy(dg1.0.get(5..).unwrap_or_default()).into_owned()
    }
}
