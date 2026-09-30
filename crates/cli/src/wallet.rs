//! A user's wallet: the passport it proves with, the shielded key, the receiver (keys, bundle,
//! channels), the contacts (one `Sender` per accepted bundle), the notes, the note tree and the
//! identity tree followed from the pool's events (their frontiers and this wallet's paths), and its
//! registration in the identity cache. Persisted as JSON (`<home>/<name>.json`), the channel states
//! through zk-encryption's serde feature; written before every broadcast (the advanced chain key
//! must never be reused).

use crate::chain::{self, TxEvents};
use crate::document::{self, Document};
use crate::emit::{InNote, MIN_NOTE_VALUE, OutNote, Transfer};
use crate::identity::{self, Registration};
use crate::tree::Tree;
use alloy::primitives::Address;
use alloy::providers::Provider;
use emit_devnet_circuits::circuits::DEPLOYMENT;
use emit_devnet_circuits::circuits::families::{
    KernelStepDocument, KernelStepDsc, KernelStepEnvelope, KernelStepMember,
    KernelStepNoteEnvelope, KernelStepRegister, KernelStepSession, KernelStepSod,
    KernelStepTransferHolder,
};
use emit_devnet_circuits::circuits::pipelines::{identity_register, member_transfer};
use noir_zk_core::StepFamily;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;
use zk_encryption_circuits::wallet::Fr;
use zk_encryption_circuits::wallet::emit::{Delivery, Emit};
use zk_encryption_circuits::wallet::poseidon::{FieldHex, Rng};
use zk_encryption_circuits::wallet::receiver::{Receiver, Scan};
use zk_encryption_circuits::wallet::sender::{ChannelWitness, Sender};

/// Chain keys a receiver holds ahead per channel.
pub const WINDOW: u64 = 8;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Note {
    /// Wei, as a decimal string.
    pub value: String,
    pub rho: String,
    pub r: String,
    pub commitment: String,
    /// The leaf index, once the pool appended it.
    pub index: Option<u64>,
    /// Who sent it (their MRZ), for a received note.
    pub from: Option<String>,
}

impl Note {
    pub fn value(&self) -> u128 {
        self.value.parse().unwrap_or(0)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Contact {
    pub bundle: String,
    pub sender: Sender,
}

#[derive(Serialize, Deserialize)]
pub struct Wallet {
    pub name: String,
    pub document: String,
    /// The funded EOA that sends this wallet's transactions (devnet: see README).
    pub key: String,
    /// The shielded spending key.
    pub sk: String,
    pub receiver: Receiver,
    pub bundle: String,
    pub contacts: BTreeMap<String, Contact>,
    pub notes: Vec<Note>,
    /// This wallet's outputs of transfers it sent, until the pool appends them.
    pub pending: Vec<Note>,
    /// The note tree (the pool's NewCommitment events), watching this wallet's notes.
    pub tree: Tree,
    /// The registration in the identity cache, if any.
    pub identity: Option<Registration>,
    /// The identity tree (the pool's IdentityRegistered events), watching this wallet's leaf.
    pub identity_tree: Tree,
    /// The last block synced.
    pub synced: u64,
}

pub fn path(home: &Path, name: &str) -> PathBuf {
    home.join(format!("{name}.json"))
}

/// What a transaction does to the pool, before the notes are chosen.
pub struct Plan {
    pub ins: Vec<Note>,
    /// (recipient pk, value, kept by this wallet)
    pub outs: [(Fr, u128, bool); 2],
    pub v_in: u128,
    pub v_out: u128,
    pub fee: u128,
    pub payout: Address,
    /// A contact's channel (handshake or ratchet), or none (a throwaway channel).
    pub to: Option<String>,
}

/// Timings and gas of one transact or register.
pub struct Receipt {
    /// The pipeline proved.
    pub pipeline: &'static str,
    pub prove_s: f64,
    pub verify_ms: f64,
    pub proof_bytes: usize,
    pub gas_used: u64,
    pub calldata: usize,
    pub block: u64,
    pub tx: String,
}

impl Wallet {
    pub fn load(home: &Path, name: &str) -> eyre::Result<Self> {
        let p = path(home, name);
        let s = std::fs::read_to_string(&p)
            .map_err(|e| eyre::eyre!("{}: {e} (zkpool identity new --name {name})", p.display()))?;
        Ok(serde_json::from_str(&s)?)
    }

    /// Writes the state atomically (a temp file renamed over the old one).
    pub fn save(&self, home: &Path) -> eyre::Result<()> {
        std::fs::create_dir_all(home)?;
        let p = path(home, &self.name);
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(tmp, p)?;
        Ok(())
    }

    pub fn sk(&self) -> Fr {
        Fr::from_hex(&self.sk)
    }

    pub fn pk(&self) -> Fr {
        Emit::pk(self.sk())
    }

    /// The registration, if the pool appended it and it is still valid at `now`.
    pub fn live_registration(&self, now: u64) -> Option<&Registration> {
        self.identity
            .as_ref()
            .filter(|r| r.index.is_some() && r.expiry >= now)
    }

    pub fn balance(&self) -> u128 {
        self.notes.iter().map(Note::value).sum()
    }

    fn nullifier(&self, n: &Note) -> Fr {
        Emit::nullifier(Emit::nk(self.sk()), Fr::from_hex(&n.rho))
    }

    /// Applies one pool transaction: appends its commitments to the tree, drops spent notes,
    /// keeps this wallet's pending outputs, and scans the Envelope for a note addressed here.
    /// Returns what was received (value, sender's MRZ, handshake or ratchet index).
    pub fn apply(&mut self, cid: Fr, t: &TxEvents) -> eyre::Result<Option<(u128, String, String)>> {
        for (leaf, i, _) in &t.identities {
            eyre::ensure!(
                *i == self.identity_tree.size,
                "identity leaf {i} out of order (the wallet has {}): resync from scratch",
                self.identity_tree.size
            );
            let mine = self.identity.as_ref().is_some_and(|r| r.leaf == leaf.hex());
            self.identity_tree.append(*leaf, mine);
            if let Some(r) = self.identity.as_mut().filter(|_| mine) {
                r.index = Some(*i);
            }
        }
        // A note addressed here, found before its commitment is appended (the tree keeps paths
        // only of the leaves it watches from their insertion).
        let received = match (
            &t.envelope,
            t.nullifiers.as_slice(),
            t.commitments.as_slice(),
        ) {
            (Some(envelope), [n0, n1], [c0, c1]) => {
                let d = Delivery {
                    cid,
                    nullifiers: [*n0, *n1],
                    commitments: [*c0, *c1],
                    envelope: envelope.clone(),
                };
                match self.receiver.scan(&d) {
                    Scan::Handshake { note, dg1 } => Some((note, dg1, "handshake".to_string())),
                    Scan::Ratchet { t, note, dg1 } => {
                        Some((note, dg1, format!("ratchet index {t}")))
                    }
                    Scan::NotMine => None,
                    Scan::Invalid(e) => {
                        eprintln!(
                            "{}: tx {} addressed here but refused: {e:?}",
                            self.name, t.tx
                        );
                        None
                    }
                }
            }
            _ => None,
        };
        if let Some((note, _, _)) = &received {
            eyre::ensure!(
                note.commitment(cid, self.pk()) == t.commitments[0].0,
                "note does not open C0"
            );
        }
        for (c, i) in &t.commitments {
            eyre::ensure!(
                *i == self.tree.size,
                "leaf {i} out of order (the wallet has {}): resync from scratch",
                self.tree.size
            );
            let pending = self.pending.iter().position(|n| n.commitment == c.hex());
            let got = received
                .as_ref()
                .filter(|(note, _, _)| *c == t.commitments[0].0 && note.value > 0);
            self.tree.append(*c, pending.is_some() || got.is_some());
            if let Some(k) = pending {
                let mut n = self.pending.remove(k);
                n.index = Some(*i);
                self.notes.push(n);
            } else if let Some((note, dg1, _)) = got
                && !self.notes.iter().any(|n| n.commitment == c.hex())
            {
                self.notes.push(Note {
                    value: note.value.to_string(),
                    rho: note.rho.hex(),
                    r: note.r.hex(),
                    commitment: c.hex(),
                    index: Some(*i),
                    from: Some(Document::mrz(dg1)),
                });
            }
        }
        let spent: Vec<String> = t.nullifiers.iter().map(|n| n.hex()).collect();
        let (gone, kept): (Vec<Note>, Vec<Note>) = std::mem::take(&mut self.notes)
            .into_iter()
            .partition(|n| spent.contains(&self.nullifier(n).hex()));
        self.notes = kept;
        for i in gone.iter().filter_map(|n| n.index) {
            self.tree.unwatch(i);
        }
        Ok(received.map(|(note, dg1, how)| (note.value, Document::mrz(&dg1), how)))
    }

    /// Catches up with the pool's events up to the latest block; prints received notes.
    pub async fn sync(
        &mut self,
        p: &impl Provider,
        pool: Address,
        home: &Path,
    ) -> eyre::Result<usize> {
        let cid = Fr::from(p.get_chain_id().await?);
        let latest = p.get_block_number().await?;
        if latest <= self.synced {
            return Ok(0);
        }
        let mut received = 0;
        for t in chain::events(p, pool, self.synced + 1, latest).await? {
            if let Some((v, mrz, how)) = self.apply(cid, &t)? {
                received += 1;
                println!(
                    "{}: received {} ETH ({how}, block {}) from {mrz}",
                    self.name,
                    crate::eth(v),
                    t.block
                );
            }
        }
        self.synced = latest;
        self.save(home)?;
        Ok(received)
    }

    /// Picks `k` notes (smallest first) worth at least `need`.
    pub fn pick(&self, need: u128, max: usize) -> eyre::Result<Vec<Note>> {
        let mut notes: Vec<Note> = self
            .notes
            .iter()
            .filter(|n| n.index.is_some())
            .cloned()
            .collect();
        notes.sort_by_key(Note::value);
        if let Some(n) = notes.iter().find(|n| n.value() >= need) {
            return Ok(vec![n.clone()]);
        }
        if max >= 2 {
            for i in 0..notes.len() {
                for j in i + 1..notes.len() {
                    if notes[i].value() + notes[j].value() >= need {
                        return Ok(vec![notes[i].clone(), notes[j].clone()]);
                    }
                }
            }
        }
        eyre::bail!(
            "no {} note(s) worth {} ETH (balance {} ETH)",
            if max >= 2 { "one or two" } else { "single" },
            crate::eth(need),
            crate::eth(self.balance())
        )
    }

    /// Builds the transfer, proves it (member_transfer: the registered holder's membership, not
    /// the passport), and sends it from the EOA.
    pub async fn execute(
        &mut self,
        plan: Plan,
        ctx: &crate::Ctx,
        p: &impl Provider,
    ) -> eyre::Result<Receipt> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let registration = self.live_registration(now).cloned().ok_or_else(|| {
            eyre::eyre!(
                "{} has no live registration: prove the passport once with `zkpool identity register`",
                self.name
            )
        })?;
        for (_, v, _) in &plan.outs {
            eyre::ensure!(
                *v == 0 || *v >= MIN_NOTE_VALUE,
                "a {} ETH note is below the minimum of {} ETH (a note is 0 or at least 1/3 ETH)",
                crate::eth(*v),
                crate::eth(MIN_NOTE_VALUE)
            );
        }
        let chain_id = p.get_chain_id().await?;
        let cid = Fr::from(chain_id);
        let root = self.tree.root();
        let sk = self.sk();
        let ins: Vec<InNote> = plan
            .ins
            .iter()
            .map(|n| {
                let index = n.index.expect("appended");
                Ok(InNote {
                    sk,
                    value: n.value(),
                    rho: Fr::from_hex(&n.rho),
                    r: Fr::from_hex(&n.r),
                    path: self.tree.path(index).ok_or_else(|| {
                        eyre::eyre!("note {index} isn't watched: resync from scratch")
                    })?,
                })
            })
            .collect::<eyre::Result<_>>()?;
        let mut ins = ins.into_iter();
        let ins = [
            ins.next().unwrap_or_else(|| InNote::dummy(sk)),
            ins.next().unwrap_or_else(|| InNote::dummy(sk)),
        ];
        let outs = plan.outs.map(|(pk, v, _)| OutNote::to(pk, v));
        // The channel: advancing it changes the state, which is written before broadcasting.
        let channel = match &plan.to {
            None => ChannelWitness::throwaway()?,
            Some(name) => {
                let c = self
                    .contacts
                    .get_mut(name)
                    .ok_or_else(|| eyre::eyre!("no contact {name} (zkpool contact add)"))?;
                match c.sender.index() {
                    None => c.sender.handshake()?,
                    Some(_) => c.sender.advance()?,
                }
            }
        };
        let payout = address_field(plan.payout);
        let t = Transfer::build(
            cid, root, ins, outs, plan.v_in, plan.v_out, plan.fee, payout, channel,
        )
        .map_err(|e| eyre::eyre!("transfer: {e:?}"))?;
        for (j, (_, v, keep)) in plan.outs.iter().enumerate() {
            if *keep && *v > 0 {
                let o = t.opening(j);
                self.pending.push(Note {
                    value: v.to_string(),
                    rho: o.rho.hex(),
                    r: o.r.hex(),
                    commitment: t.commitments[j].hex(),
                    index: None,
                    from: None,
                });
            }
        }
        self.save(&ctx.home)?;

        // Membership in the identity tree, the session, DG1 (committed afresh) sealed, the transfer
        // bound to the registered key, the note sealed.
        let doc = document::by_name(&self.document)?;
        let e = |what: &str| {
            let what = what.to_string();
            move |err: noir_zk_core::Error| eyre::eyre!("{what}: {err}")
        };
        let index = registration.index.expect("live");
        let path = self.identity_tree.path(index).ok_or_else(|| {
            eyre::eyre!("identity leaf {index} isn't watched: resync from scratch")
        })?;
        let salt = Rng::field();
        let member = identity::member_inputs(
            self.identity_tree.root(),
            now,
            sk,
            &doc.dg1,
            salt,
            registration.expiry,
            registration.blinding()?,
            &path,
            t.ctx,
        );
        let artifacts = ctx.pool(&[])?.merged();
        let start = Instant::now();
        let proof = prove_member(
            &artifacts,
            member,
            doc.envelope(salt, t.ctx, t.channel.s),
            &t,
        )?;
        let prove_s = start.elapsed().as_secs_f64();
        let (pipeline, name) = (member_transfer::ROOT, "member_transfer");
        let proof = proof.to_bytes();
        let proof_bytes = proof.len();
        // What ZK_VERIFY will do, locally first (and timed: the precompile's gas is priced on it).
        let start = Instant::now();
        emit_devnet_circuits::verify(&pipeline, &proof).map_err(e("local verification"))?;
        let verify_ms = start.elapsed().as_secs_f64() * 1e3;

        let signer: alloy::signers::local::PrivateKeySigner = self.key.parse()?;
        let sender = alloy::providers::ProviderBuilder::new()
            .wallet(signer)
            .connect(&ctx.rpc)
            .await?;
        let sent = chain::transact(
            &sender,
            ctx.pool_address()?,
            chain::Transact {
                pipeline,
                root,
                nullifiers: t.nullifiers,
                commitments: t.commitments,
                v_in: t.v_in,
                v_out: t.v_out,
                fee: t.fee,
                payout: plan.payout,
                pq_ciphertext: t.channel.kem.handshake.ct.to_bytes(),
                proof,
            },
        )
        .await;
        let sent = match sent {
            Ok(s) => s,
            Err(err) => {
                // Nothing was appended: forget the pending outputs. A ratchet key stays consumed
                // (the receiver's window skips it); a handshake nobody saw opened no channel, so
                // the contact starts over with a fresh one (its C_t is never reused).
                self.pending
                    .retain(|n| !t.commitments.iter().any(|c| c.hex() == n.commitment));
                if let (Some(name), true) = (&plan.to, t.channel.is_handshake)
                    && let Some(c) = self.contacts.get_mut(name)
                {
                    let bundle = base64_bundle(&c.bundle)?;
                    c.sender = Sender::accept(&bundle, chain_id, now, &|_| None)
                        .map_err(|e| eyre::eyre!("bundle: {e:?}"))?;
                }
                self.save(&ctx.home)?;
                return Err(err);
            }
        };
        self.sync(p, ctx.pool_address()?, &ctx.home).await?;
        Ok(Receipt {
            pipeline: name,
            prove_s,
            verify_ms,
            proof_bytes,
            gas_used: sent.gas_used,
            calldata: sent.calldata,
            block: sent.block,
            tx: sent.tx.to_string(),
        })
    }

    /// Registers this wallet's key with its passport in the pool's identity cache: proves the
    /// identity_register pipeline once (the document in the scope of this epoch, the leaf valid
    /// until the epoch ends or the passport expires, whichever is first) and sends `register`. In
    /// the epoch's last RENEWAL_WINDOW it registers for the next epoch instead (valid at once, until
    /// that epoch ends). Refuses when that wouldn't outlast the live registration, unless `force`.
    pub async fn register(
        &mut self,
        ctx: &crate::Ctx,
        p: &impl Provider,
        force: bool,
    ) -> eyre::Result<Receipt> {
        let pool_address = ctx.pool_address()?;
        let c = chain::EmitV2Pool::new(pool_address, p);
        let epoch_len: u64 = c.IDENTITY_EPOCH().call().await?.to();
        let renewal: u64 = c.RENEWAL_WINDOW().call().await?.to();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let mut epoch = now / epoch_len;
        if now + renewal >= (epoch + 1) * epoch_len {
            epoch += 1;
        }
        let doc = document::by_name(&self.document)?;
        let expiry = doc.expires()?.min((epoch + 1) * epoch_len - 1);
        if let Some(r) = self.live_registration(now)
            && r.expiry >= expiry
            && !force
        {
            eyre::bail!(
                "{} is registered until {} (identity leaf {}); --force to register again",
                self.name,
                r.expiry,
                r.index.unwrap_or_default()
            );
        }
        let scope = c
            .registrationScope(alloy::primitives::U256::from(epoch))
            .call()
            .await?;
        let (w, salt) = doc.eid(ctx.registry()?, now, &format!("{scope:#x}"))?;
        let labels = [w.selection.dsc, w.selection.sod, w.selection.document];
        let pool = ctx.pool(&labels)?;
        let artifacts = pool.merged();
        let sk = self.sk();
        // The leaf's blinding: without it, anyone who knows the holder's address and MRZ could
        // recompute the leaf and find this registration on-chain.
        let blinding = Rng::field();
        let e = |what: &str| {
            let what = what.to_string();
            move |err: noir_zk_core::Error| eyre::eyre!("{what}: {err}")
        };
        let start = Instant::now();
        let (proof, _) = identity_register::fold(&artifacts)
            .map_err(e("pipeline"))?
            .app(KernelStepDsc::select(&labels[0], w.dsc).map_err(e("dsc"))?)
            .map_err(e("dsc"))?
            .app(KernelStepSod::select(&labels[1], w.sod).map_err(e("sod"))?)
            .map_err(e("sod"))?
            .app(KernelStepDocument::select(&labels[2], w.document).map_err(e("document"))?)
            .map_err(e("document"))?
            .app(
                KernelStepRegister::select(
                    "register",
                    identity::register_inputs(salt, &doc.dg1, sk, expiry, blinding),
                )
                .map_err(e("register"))?,
            )
            .map_err(e("register"))?
            .hiding(&DEPLOYMENT)
            .map_err(e("prove"))?;
        let prove_s = start.elapsed().as_secs_f64();
        let proof = proof.to_bytes();
        let proof_bytes = proof.len();
        let start = Instant::now();
        emit_devnet_circuits::verify(&identity_register::ROOT, &proof)
            .map_err(e("local verification"))?;
        let verify_ms = start.elapsed().as_secs_f64() * 1e3;

        let leaf = identity::leaf(sk, &doc.dg1, expiry, blinding).hex();
        let previous = self.identity.clone();
        self.identity = Some(Registration {
            leaf: leaf.clone(),
            index: None,
            salt: salt.hex(),
            expiry,
            blinding: Some(blinding.hex()),
        });
        self.save(&ctx.home)?;
        let signer: alloy::signers::local::PrivateKeySigner = self.key.parse()?;
        let sender = alloy::providers::ProviderBuilder::new()
            .wallet(signer)
            .connect(&ctx.rpc)
            .await?;
        let sent = chain::register(&sender, pool_address, proof).await;
        let sent = match sent {
            Ok(s) => s,
            Err(err) => {
                self.identity = previous;
                self.save(&ctx.home)?;
                return Err(err);
            }
        };
        if let Some(i) = previous.and_then(|r| r.index) {
            self.identity_tree.unwatch(i);
        }
        self.sync(p, pool_address, &ctx.home).await?;
        eyre::ensure!(
            self.live_registration(now).is_some(),
            "the pool registered a leaf other than the wallet's {leaf}"
        );
        Ok(Receipt {
            pipeline: "identity_register",
            prove_s,
            verify_ms,
            proof_bytes,
            gas_used: sent.gas_used,
            calldata: sent.calldata,
            block: sent.block,
            tx: sent.tx.to_string(),
        })
    }

    /// A new identity: the passport, a fresh shielded key and receiver keys, the bundle.
    pub fn create(name: &str, document: &str, key: String, chain_id: u64) -> eyre::Result<Self> {
        document::by_name(document)?;
        let sk = Rng::field();
        let receiver = Receiver::generate(Emit::pk(sk), WINDOW);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let bundle = zk_encryption_circuits::wallet::bundle::Bundle {
            chain_id,
            pk_b: receiver.pk(),
            v: receiver.keys().public.grumpkin,
            pq: receiver.keys().public.pq_commitment,
            ek: zk_encryption_circuits::wallet::bundle::Ek::Inline(receiver.keys().ek().to_vec()),
            not_before: now - 60,
            not_after: now + 30 * 86_400,
            sig: None,
        };
        Ok(Self {
            name: name.into(),
            document: document.into(),
            key,
            sk: sk.hex(),
            bundle: bundle.to_base64url(),
            receiver,
            contacts: BTreeMap::new(),
            notes: vec![],
            pending: vec![],
            tree: Tree::default(),
            identity: None,
            identity_tree: Tree::default(),
            synced: 0,
        })
    }
}

/// Folds member_transfer: identity_member (`member`), the session, the DG1 envelope (`envelope`),
/// transfer_holder and the note envelope of `t`.
pub fn prove_member(
    artifacts: &dyn noir_zk_core::Artifacts,
    member: String,
    envelope: String,
    t: &Transfer,
) -> eyre::Result<emit_devnet_circuits::FoldedProof> {
    let e = |what: &'static str| move |err: noir_zk_core::Error| eyre::eyre!("{what}: {err}");
    let (proof, _) = member_transfer::fold(artifacts)
        .map_err(e("pipeline"))?
        .app(KernelStepMember::select("identity_member", member).map_err(e("member"))?)
        .map_err(e("member"))?
        .app(
            KernelStepSession::select("channel_session", t.session_inputs())
                .map_err(e("session"))?,
        )
        .map_err(e("session"))?
        .app(KernelStepEnvelope::select("channel_envelope", envelope).map_err(e("envelope"))?)
        .map_err(e("envelope"))?
        .app(
            KernelStepTransferHolder::select("transfer_holder", t.inputs())
                .map_err(e("transfer"))?,
        )
        .map_err(e("transfer"))?
        .app(
            KernelStepNoteEnvelope::select("channel_envelope", t.note_inputs())
                .map_err(e("note"))?,
        )
        .map_err(e("note"))?
        .hiding(&DEPLOYMENT)
        .map_err(e("prove"))?;
    Ok(proof)
}

/// An address as the field the transfer app takes (`payout_recipient`): its 20 bytes big-endian.
pub fn address_field(a: Address) -> Fr {
    use ark_ff::PrimeField;
    Fr::from_be_bytes_mod_order(a.as_slice())
}

/// A base64url bundle's bytes.
pub fn base64_bundle(b: &str) -> eyre::Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b.trim())
        .map_err(|e| eyre::eyre!("bundle: not base64url: {e}"))
}
