//! The identity cache (crates/circuits/noir/lib/identity_cache): the registration leaf, and the
//! register and identity_member apps' inputs.

use crate::tree::Path;
use serde::{Deserialize, Serialize};
use toml::{Table, Value};
use zk_encryption_circuits::wallet::Fr;
use zk_encryption_circuits::wallet::emit::{Dg1, Emit};
use zk_encryption_circuits::wallet::poseidon::{FieldHex, Poseidon};

/// This wallet's registration in the pool's identity tree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Registration {
    pub leaf: String,
    /// The leaf index, once the pool appended it.
    pub index: Option<u64>,
    /// The salt of the registration's DG1 commitment (the document step's).
    pub salt: String,
    /// Unix seconds: the last second the registration is valid.
    pub expiry: u64,
}

/// The leaf `H(IDENTITY, H(PK, sk), H(payload), expiry)`.
pub fn leaf(sk: Fr, dg1: &Dg1, expiry: u64) -> Fr {
    Poseidon::hash(&[
        Poseidon::domain("emit-v2/identity"),
        Emit::pk(sk),
        Poseidon::hash(&dg1.to_payload()),
        Fr::from(expiry),
    ])
}

fn s(f: Fr) -> Value {
    Value::String(f.hex())
}

/// The register app's `Prover.toml`.
pub fn register_inputs(salt: Fr, dg1: &Dg1, sk: Fr, expiry: u64) -> String {
    let mut buf = dg1.0.clone();
    buf.resize(Dg1::MAX, 0);
    let mut t = Table::new();
    t.insert("payload_salt".into(), s(salt));
    t.insert(
        "dg1".into(),
        Value::Array(buf.iter().map(|b| Value::Integer(*b as i64)).collect()),
    );
    t.insert("sk".into(), s(sk));
    t.insert("expiry".into(), Value::String(expiry.to_string()));
    toml::to_string(&t).expect("toml")
}

/// The identity_member app's `Prover.toml`.
#[allow(clippy::too_many_arguments)]
pub fn member_inputs(
    root: Fr,
    date: u64,
    sk: Fr,
    dg1: &Dg1,
    salt: Fr,
    expiry: u64,
    path: &Path,
    ctx: Fr,
) -> String {
    let mut t = Table::new();
    t.insert("identity_root".into(), s(root));
    t.insert("date".into(), Value::String(date.to_string()));
    t.insert("sk".into(), s(sk));
    t.insert(
        "payload".into(),
        Value::Array(dg1.to_payload().iter().map(|f| s(*f)).collect()),
    );
    t.insert("payload_salt".into(), s(salt));
    t.insert("expiry".into(), Value::String(expiry.to_string()));
    t.insert("index".into(), Value::String(path.index.to_string()));
    t.insert(
        "path".into(),
        Value::Array(path.siblings.iter().map(|f| s(*f)).collect()),
    );
    t.insert("ctx".into(), s(ctx));
    toml::to_string(&t).expect("toml")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::Tree;

    /// The domain is the circuit's (identity_cache::IDENTITY), and a registered leaf's path
    /// opens to the identity tree's root.
    #[test]
    fn domain_and_path_match_the_circuits() {
        assert_eq!(
            Poseidon::domain("emit-v2/identity").hex(),
            "0x00000000000000000000000000000000656d69742d76322f6964656e74697479"
        );
        let dg1 = crate::document::by_name("us_rsa4096_rsa2048")
            .expect("fixture")
            .dg1;
        let l = leaf(Fr::from(7u64), &dg1, 2_000_000_000);
        let tree = Tree::from_leaves(vec![Fr::from(1u64), l, Fr::from(3u64)]);
        assert_eq!(tree.path(1).root(l), tree.root());
    }
}
