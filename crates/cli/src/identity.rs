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
    /// The leaf's blinding (uniform random, from the OS CSPRNG at registration). A registration
    /// stored before the leaf was blinded has none and can't prove membership.
    #[serde(default)]
    pub blinding: Option<String>,
}

impl Registration {
    pub fn blinding(&self) -> eyre::Result<Fr> {
        self.blinding.as_deref().map(Fr::from_hex).ok_or_else(|| {
            eyre::eyre!(
                "the stored registration (leaf {}) has no blinding: it predates the blinded \
                 identity leaf; register again with `identity register --force` (or use --full-passport)",
                self.leaf
            )
        })
    }
}

/// The leaf `H(IDENTITY, H(PK, sk), H(payload), expiry, blinding)`.
pub fn leaf(sk: Fr, dg1: &Dg1, expiry: u64, blinding: Fr) -> Fr {
    Poseidon::hash(&[
        Poseidon::domain(IDENTITY),
        Emit::pk(sk),
        Poseidon::hash(&dg1.to_payload()),
        Fr::from(expiry),
        blinding,
    ])
}

/// The leaf's domain (identity_cache::IDENTITY; v2: the blinded leaf).
const IDENTITY: &str = "emit-v2/identity/v2";

fn s(f: Fr) -> Value {
    Value::String(f.hex())
}

/// The register app's `Prover.toml`.
pub fn register_inputs(salt: Fr, dg1: &Dg1, sk: Fr, expiry: u64, blinding: Fr) -> String {
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
    t.insert("blinding".into(), s(blinding));
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
    blinding: Fr,
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
    t.insert("blinding".into(), s(blinding));
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
            Poseidon::domain(IDENTITY).hex(),
            "0x00000000000000000000000000656d69742d76322f6964656e746974792f7632"
        );
        let dg1 = crate::document::by_name("us_rsa4096_rsa2048")
            .expect("fixture")
            .dg1;
        let l = leaf(Fr::from(7u64), &dg1, 2_000_000_000, Fr::from(5u64));
        assert_ne!(l, leaf(Fr::from(7u64), &dg1, 2_000_000_000, Fr::from(6u64)));
        let tree = Tree::from_leaves(vec![Fr::from(1u64), l, Fr::from(3u64)]);
        assert_eq!(tree.path(1).root(l), tree.root());
    }

    /// A registration stored before the leaf was blinded still loads, and refuses to prove.
    #[test]
    fn a_registration_without_blinding_fails_clearly() {
        let r: Registration =
            serde_json::from_str(r#"{"leaf":"0x01","index":0,"salt":"0x02","expiry":1}"#)
                .expect("an old registration loads");
        let err = r.blinding().expect_err("no blinding");
        assert!(
            format!("{err}").contains("identity register --force"),
            "{err}"
        );
    }

    /// Folds a deposit on member_transfer by `spender` with `registered`'s registration.
    fn member_deposit(registered: Fr, spender: Fr) -> eyre::Result<Vec<u8>> {
        use crate::emit::{InNote, OutNote, Transfer};
        use zk_encryption_circuits::wallet::sender::ChannelWitness;
        let doc = crate::document::by_name("us_rsa4096_rsa2048")?;
        let (date, expiry) = (1_790_467_200, 1_790_812_799);
        let blinding = Fr::from(0x2bd1u64);
        let itree = Tree::from_leaves(vec![leaf(registered, &doc.dg1, expiry, blinding)]);
        let cid = Fr::from(3607u64);
        let t = Transfer::build(
            cid,
            Tree::default().root(),
            [InNote::dummy(spender), InNote::dummy(spender)],
            [
                OutNote::to(Emit::pk(spender), 5),
                OutNote::to(Emit::pk(spender), 0),
            ],
            5,
            0,
            0,
            Fr::from(0u64),
            ChannelWitness::throwaway()?,
        )
        .map_err(|e| eyre::eyre!("{e:?}"))?;
        let salt = Fr::from(99u64);
        let member = member_inputs(
            itree.root(),
            date,
            registered,
            &doc.dg1,
            salt,
            expiry,
            blinding,
            &itree.path(0),
            t.ctx,
        );
        let emit = emit_devnet_circuits::emit_artifacts();
        let channel = zk_encryption_circuits::artifacts();
        let artifacts =
            noir_zk_core::Merged::new(&[&emit, &channel, &noir_zk_backend::kernels::Kernels]);
        let proof = crate::wallet::prove_member(
            &artifacts,
            member,
            doc.envelope(salt, t.ctx, t.channel.s),
            &t,
        )?
        .to_bytes();
        emit_devnet_circuits::verify(
            &emit_devnet_circuits::circuits::pipelines::member_transfer::ROOT,
            &proof,
        )?;
        Ok(proof)
    }

    /// The kernel binds transfer_holder's holder tag to identity_member's: only the registered
    /// key spends on member_transfer (both apps are satisfiable alone; the fold is not).
    #[test]
    #[ignore = "proves (bb's CRS): cargo test --release -- --ignored holder"]
    fn holder_binding_is_enforced_by_the_kernel() {
        let (alice, bob) = (Fr::from(11u64), Fr::from(22u64));
        member_deposit(alice, alice).expect("the registered holder proves");
        let err = member_deposit(alice, bob).expect_err("another key must not");
        // The kernel step folding transfer_holder refuses its layout's holder_tag binding.
        assert!(
            format!("{err:#}").starts_with("transfer: unsatisfied: kernel_step"),
            "{err:#}"
        );
    }
}
