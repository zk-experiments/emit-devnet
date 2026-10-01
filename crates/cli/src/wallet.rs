//! A user's wallet: the passport it proves with, the shielded key, the receiver (keys, bundle,
//! channels), the contacts (one `Sender` per accepted bundle), the notes, the escrows (addressed
//! here, awaiting this wallet's resolve; and sent, until they close), the note tree and the identity
//! tree followed from the pool's events (their frontiers and this wallet's paths), and its
//! registration in the identity cache. Persisted as JSON (`<home>/<name>.json`), the channel states
//! through zk-encryption's serde feature; written before every broadcast (the advanced chain key
//! must never be reused).

use crate::chain::{self, EnvelopeEvent, TxEvents};
use crate::document::{self, Document};
use crate::emit::{InNote, MIN_NOTE_VALUE, OutNote, Transfer, resolve_inputs};
use crate::identity::{self, Registration};
use crate::mailbox;
use crate::tree::Tree;
use alloy::primitives::Address;
use alloy::providers::Provider;
use emit_circuits::circuits::DEPLOYMENT;
use emit_circuits::circuits::families::{
    KernelStepDg1Envelope, KernelStepDocument, KernelStepDsc, KernelStepEscrowResolve,
    KernelStepMember, KernelStepNoteEnvelope, KernelStepRegister, KernelStepSession, KernelStepSod,
    KernelStepTransferHolder,
};
use emit_circuits::circuits::pipelines::{identity_register, member_resolve, member_transfer};
use emit_protocol::{Action, ChainCommitment, EnvCommit, Envelope, EscrowEventKind, Resolve};
use noir_zk_core::StepFamily;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;
use zk_encryption_circuits::wallet::Fr;
use zk_encryption_circuits::wallet::emit::{Delivery, Emit, NoteOpening};
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

/// A transaction's `Escrowed`, as the scan reads it.
struct Opened {
    c0: Fr,
    c_t: ChainCommitment,
    env_commit: EnvCommit,
    deadline: u64,
}

/// An escrowed note addressed to this wallet (or its own output 0), awaiting its resolve.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Escrow {
    /// The note commitment C0 the pool holds.
    pub c0: String,
    /// The transfer's chain commitment (its off-chain envelope's key).
    pub c_t: String,
    pub value: String,
    pub rho: String,
    pub r: String,
    /// The last second it may be accepted (0: not yet seen on-chain).
    pub deadline: u64,
    /// Who sent it (their MRZ), for a received note.
    pub from: Option<String>,
    /// handshake, ratchet index t, or own.
    pub how: String,
}

impl Escrow {
    pub fn value(&self) -> u128 {
        self.value.parse().unwrap_or(0)
    }

    fn opening(&self) -> NoteOpening {
        NoteOpening {
            value: self.value(),
            rho: Fr::from_hex(&self.rho),
            r: Fr::from_hex(&self.r),
        }
    }
}

/// An escrow this wallet created, until it closes; its refund note waits in `pending`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SentEscrow {
    pub c0: String,
    pub c_t: String,
    /// The refund note's commitment C_r.
    pub refund: String,
    /// The contact paid, if any.
    pub to: Option<String>,
    pub value: String,
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
    /// This wallet's outputs of transfers it sent (change, refunds, accepted escrows), until the pool
    /// appends them.
    pub pending: Vec<Note>,
    /// Escrowed notes addressed here, awaiting this wallet's resolve.
    #[serde(default)]
    pub escrows: Vec<Escrow>,
    /// Escrows of this wallet's transfers, until they close.
    #[serde(default)]
    pub sent: Vec<SentEscrow>,
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
    /// keeps this wallet's pending outputs, scans an escrow for a note addressed here (with its
    /// off-chain envelope, if one was delivered), and forgets closed escrows. Returns what was
    /// received into escrow (value, sender's MRZ, handshake or ratchet index).
    pub fn apply(
        &mut self,
        cid: Fr,
        t: &TxEvents,
        home: &Path,
    ) -> eyre::Result<Option<(u128, String, String)>> {
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
        let opened = t.escrow.iter().find_map(|l| match &l.kind {
            EscrowEventKind::Opened {
                note_commitment,
                chain_commitment,
                env_commit,
                deadline,
            } => Some(Opened {
                c0: note_commitment.to_fr(),
                c_t: *chain_commitment,
                env_commit: *env_commit,
                deadline: *deadline,
            }),
            EscrowEventKind::Closed { .. } => None,
        });
        let received = match (
            &opened,
            &t.envelope,
            t.nullifiers.as_slice(),
            t.commitments.first(),
        ) {
            (Some(x), Some(e), [n0, n1], Some(c1))
                if !self.sent.iter().any(|s| s.c0 == x.c0.hex()) =>
            {
                self.scan(cid, x, e, [*n0, *n1], *c1, home, &t.tx)?
            }
            _ => None,
        };
        if let Some(x) = &opened
            && let Some(e) = self.escrows.iter_mut().find(|e| e.c0 == x.c0.hex())
        {
            e.deadline = x.deadline;
        }
        for (c, i) in &t.commitments {
            eyre::ensure!(
                *i == self.tree.size,
                "leaf {i} out of order (the wallet has {}): resync from scratch",
                self.tree.size
            );
            let pending = self.pending.iter().position(|n| n.commitment == c.hex());
            self.tree.append(*c, pending.is_some());
            if let Some(k) = pending {
                let mut n = self.pending.remove(k);
                n.index = Some(*i);
                self.notes.push(n);
            }
        }
        // After the appends: a reject or refund appends the refund note in the same transaction.
        let closed = t.escrow.iter().filter_map(|l| match &l.kind {
            EscrowEventKind::Closed { note_commitment } => Some(note_commitment.to_fr().hex()),
            EscrowEventKind::Opened { .. } => None,
        });
        for c0 in closed {
            if let Some(k) = self.escrows.iter().position(|e| e.c0 == c0) {
                let e = self.escrows.remove(k);
                mailbox::remove(home, Fr::from_hex(&e.c_t));
            }
            if let Some(k) = self.sent.iter().position(|s| s.c0 == c0) {
                let s = self.sent.remove(k);
                self.pending.retain(|n| n.commitment != s.refund);
                mailbox::remove(home, Fr::from_hex(&s.c_t));
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
        Ok(received)
    }

    /// Scans an escrowed transfer with its off-chain envelope: a note addressed here becomes an
    /// escrow awaiting this wallet's resolve. Without an envelope (none delivered, or not opening
    /// `env_commit`) there is nothing to scan.
    #[allow(clippy::too_many_arguments)]
    fn scan(
        &mut self,
        cid: Fr,
        x: &Opened,
        e: &EnvelopeEvent,
        nullifiers: [Fr; 2],
        c1: (Fr, u64),
        home: &Path,
        tx: &alloy::primitives::B256,
    ) -> eyre::Result<Option<(u128, String, String)>> {
        let Some(sealed) = mailbox::get(home, x.c_t.to_fr())? else {
            return Ok(None);
        };
        if sealed.commit().ok() != Some(x.env_commit) {
            eprintln!(
                "{}: tx {tx}: the envelope under C_t {} doesn't open env_commit: ignored",
                self.name,
                x.c_t.to_hex()
            );
            return Ok(None);
        }
        let d = Delivery {
            cid,
            nullifiers,
            commitments: [(x.c0, 0), c1],
            envelope: e.with(&sealed)?,
        };
        let (note, dg1, how) = match self.receiver.scan(&d) {
            Scan::Handshake { note, dg1 } => (note, dg1, "handshake".to_string()),
            Scan::Ratchet { t, note, dg1 } => (note, dg1, format!("ratchet index {t}")),
            Scan::NotMine => return Ok(None),
            Scan::Invalid(err) => {
                eprintln!("{}: tx {tx} addressed here but refused: {err:?}", self.name);
                return Ok(None);
            }
        };
        eyre::ensure!(
            note.commitment(cid, self.pk()) == x.c0,
            "note does not open C0"
        );
        let from = Document::mrz(&dg1);
        self.escrows.push(Escrow {
            c0: x.c0.hex(),
            c_t: x.c_t.to_fr().hex(),
            value: note.value.to_string(),
            rho: note.rho.hex(),
            r: note.r.hex(),
            deadline: x.deadline,
            from: Some(from.clone()),
            how: how.clone(),
        });
        Ok(Some((note.value, from, how)))
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
            if let Some((v, mrz, how)) = self.apply(cid, &t, home)? {
                received += 1;
                println!(
                    "{}: received {} ETH ({how}, block {}) from {mrz}, in escrow: zkpool resolve",
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

    /// The live registration and the identity_member app's inputs in context `ctx`, with the salt of
    /// the fresh DG1 commitment it links out, and the passport.
    fn member(&self, now: u64, ctx: Fr) -> eyre::Result<(String, Fr, Document)> {
        let registration = self.live_registration(now).cloned().ok_or_else(|| {
            eyre::eyre!(
                "{} has no live registration: prove the passport once with `zkpool identity register`",
                self.name
            )
        })?;
        let doc = document::by_name(&self.document)?;
        let index = registration.index.expect("live");
        let path = self.identity_tree.path(index).ok_or_else(|| {
            eyre::eyre!("identity leaf {index} isn't watched: resync from scratch")
        })?;
        let salt = Rng::field();
        let inputs = identity::member_inputs(
            self.identity_tree.root(),
            now,
            self.sk(),
            &doc.dg1,
            salt,
            registration.expiry,
            registration.blinding()?,
            &path,
            ctx,
        );
        Ok((inputs, salt, doc))
    }

    /// Builds the transfer, proves it (member_transfer: the registered holder's membership, not
    /// the passport), puts its off-chain envelope in the mailbox when it pays a contact, and sends it
    /// from the EOA. Output 0 is escrowed: its refund note waits in `pending` until the escrow
    /// closes, and when it is this wallet's own (a split), the wallet accepts it at once. Returns the
    /// transfer's receipt, then the resolve's if there was one.
    pub async fn execute(
        &mut self,
        plan: Plan,
        ctx: &crate::Ctx,
        p: &impl Provider,
    ) -> eyre::Result<Vec<Receipt>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        eyre::ensure!(
            self.live_registration(now).is_some(),
            "{} has no live registration: prove the passport once with `zkpool identity register`",
            self.name
        );
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
        // Output 1 (change, a kept note) is appended at once; output 0 is escrowed, its refund
        // waiting here until the escrow closes.
        let (_, v1, keep1) = plan.outs[1];
        if keep1 && v1 > 0 {
            let o = t.opening(1);
            self.pending.push(Note {
                value: v1.to_string(),
                rho: o.rho.hex(),
                r: o.r.hex(),
                commitment: t.commitments[1].hex(),
                index: None,
                from: None,
            });
        }
        let (_, v0, keep0) = plan.outs[0];
        if v0 > 0 {
            let o = t.refund_opening();
            self.pending.push(Note {
                value: v0.to_string(),
                rho: o.rho.hex(),
                r: o.r.hex(),
                commitment: t.refund.hex(),
                index: None,
                from: None,
            });
            self.sent.push(SentEscrow {
                c0: t.commitments[0].hex(),
                c_t: t.channel.c_t.hex(),
                refund: t.refund.hex(),
                to: plan.to.clone(),
                value: v0.to_string(),
            });
            if keep0 {
                let o = t.opening(0);
                self.escrows.push(Escrow {
                    c0: t.commitments[0].hex(),
                    c_t: t.channel.c_t.hex(),
                    value: v0.to_string(),
                    rho: o.rho.hex(),
                    r: o.r.hex(),
                    deadline: 0,
                    from: None,
                    how: "own".into(),
                });
            }
        }
        self.save(&ctx.home)?;

        // Membership in the identity tree, the session, DG1 (committed afresh) sealed, the transfer
        // bound to the registered key, the note sealed.
        let (member, salt, doc) = self.member(now, t.ctx)?;
        if plan.to.is_some() {
            // The envelope the receiver needs, off-chain and before the transaction exists.
            let sealed = Envelope::from_parts(
                &t.channel.kem.handshake.ct,
                &doc.sealed_dg1(t.ctx, t.channel.s)?,
            );
            mailbox::put(&ctx.home, t.channel.c_t, &sealed)?;
        }
        let e = |what: &str| {
            let what = what.to_string();
            move |err: noir_zk_core::Error| eyre::eyre!("{what}: {err}")
        };
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
        emit_circuits::verify(&pipeline, &proof).map_err(e("local verification"))?;
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
                proof,
            },
        )
        .await;
        let sent = match sent {
            Ok(s) => s,
            Err(err) => {
                // Nothing was appended or escrowed: forget the pending outputs, the escrow and the
                // envelope. A ratchet key stays consumed (the receiver's window skips it); a
                // handshake nobody saw opened no channel, so the contact starts over with a fresh
                // one (its C_t is never reused).
                let c0 = t.commitments[0].hex();
                self.pending.retain(|n| {
                    !t.commitments.iter().any(|c| c.hex() == n.commitment)
                        && n.commitment != t.refund.hex()
                });
                self.sent.retain(|s| s.c0 != c0);
                self.escrows.retain(|e| e.c0 != c0);
                mailbox::remove(&ctx.home, t.channel.c_t);
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
        let mut receipts = vec![Receipt {
            pipeline: name,
            prove_s,
            verify_ms,
            proof_bytes,
            gas_used: sent.gas_used,
            calldata: sent.calldata,
            block: sent.block,
            tx: sent.tx.to_string(),
        }];
        if keep0 && v0 > 0 {
            let c0 = t.commitments[0].hex();
            receipts.push(self.resolve(&c0, Action::Accept, 0, ctx, p).await?);
        }
        Ok(receipts)
    }

    /// Resolves an escrow addressed here (by its C0): proves member_resolve (this wallet's
    /// membership, then the resolve) and sends it. Accept appends the note less `fee` for this
    /// wallet; reject hands it back to the sender.
    pub async fn resolve(
        &mut self,
        c0: &str,
        action: Action,
        fee: u128,
        ctx: &crate::Ctx,
        p: &impl Provider,
    ) -> eyre::Result<Receipt> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let escrow = self
            .escrows
            .iter()
            .find(|e| e.c0 == c0)
            .cloned()
            .ok_or_else(|| eyre::eyre!("no escrow {c0} addressed here (zkpool escrows)"))?;
        if action == Action::Accept && escrow.deadline != 0 {
            eyre::ensure!(
                now <= escrow.deadline,
                "the escrow's window closed at {}: only a reject or the sender's refund remain",
                escrow.deadline
            );
        }
        let cid = Fr::from(p.get_chain_id().await?);
        let r = Resolve::build(cid, self.sk(), escrow.opening(), action, fee, Rng::field())
            .map_err(|e| eyre::eyre!("resolve: {e}"))?;
        eyre::ensure!(r.c0.hex() == escrow.c0, "the escrow's opening is not C0's");
        let kept = r.kept();
        if action == Action::Accept && kept.value > 0 {
            self.pending.push(Note {
                value: kept.value.to_string(),
                rho: kept.rho.hex(),
                r: kept.r.hex(),
                commitment: r.c_out.hex(),
                index: None,
                from: escrow.from.clone(),
            });
        }
        self.save(&ctx.home)?;

        let e = |what: &'static str| move |err: noir_zk_core::Error| eyre::eyre!("{what}: {err}");
        let (member, _, _) = self.member(now, r.ctx)?;
        let artifacts = ctx.pool(&[])?.merged();
        let start = Instant::now();
        let (proof, _) = member_resolve::fold(&artifacts)
            .map_err(e("pipeline"))?
            .app(KernelStepMember::select("identity_member", member).map_err(e("member"))?)
            .map_err(e("member"))?
            .app(
                KernelStepEscrowResolve::select("escrow_resolve", resolve_inputs(&r))
                    .map_err(e("resolve"))?,
            )
            .map_err(e("resolve"))?
            .hiding(&DEPLOYMENT)
            .map_err(e("prove"))?;
        let prove_s = start.elapsed().as_secs_f64();
        let proof = proof.to_bytes();
        let proof_bytes = proof.len();
        let start = Instant::now();
        emit_circuits::verify(&member_resolve::ROOT, &proof).map_err(e("local verification"))?;
        let verify_ms = start.elapsed().as_secs_f64() * 1e3;

        let signer: alloy::signers::local::PrivateKeySigner = self.key.parse()?;
        let sender = alloy::providers::ProviderBuilder::new()
            .wallet(signer)
            .connect(&ctx.rpc)
            .await?;
        let sent = match chain::resolve(&sender, ctx.pool_address()?, proof).await {
            Ok(s) => s,
            Err(err) => {
                self.pending.retain(|n| n.commitment != r.c_out.hex());
                self.save(&ctx.home)?;
                return Err(err);
            }
        };
        self.sync(p, ctx.pool_address()?, &ctx.home).await?;
        Ok(Receipt {
            pipeline: "member_resolve",
            prove_s,
            verify_ms,
            proof_bytes,
            gas_used: sent.gas_used,
            calldata: sent.calldata,
            block: sent.block,
            tx: sent.tx.to_string(),
        })
    }

    /// Hands back an escrow this wallet sent whose window passed: its refund note is appended here.
    pub async fn refund(
        &mut self,
        c0: &str,
        ctx: &crate::Ctx,
        p: &impl Provider,
    ) -> eyre::Result<Receipt> {
        eyre::ensure!(
            self.sent.iter().any(|s| s.c0 == c0),
            "no escrow {c0} sent from here (zkpool escrows)"
        );
        let signer: alloy::signers::local::PrivateKeySigner = self.key.parse()?;
        let sender = alloy::providers::ProviderBuilder::new()
            .wallet(signer)
            .connect(&ctx.rpc)
            .await?;
        let sent = chain::refund(&sender, ctx.pool_address()?, Fr::from_hex(c0)).await?;
        self.sync(p, ctx.pool_address()?, &ctx.home).await?;
        Ok(Receipt {
            pipeline: "no proof",
            prove_s: 0.0,
            verify_ms: 0.0,
            proof_bytes: 0,
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
        emit_circuits::verify(&identity_register::ROOT, &proof).map_err(e("local verification"))?;
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
            escrows: vec![],
            sent: vec![],
            tree: Tree::default(),
            identity: None,
            identity_tree: Tree::default(),
            synced: 0,
        })
    }
}

/// Folds member_transfer: identity_member (`member`), the session, the DG1 envelope (`envelope`,
/// only its ciphertext's commitment public), transfer_holder and the note envelope of `t`.
pub fn prove_member(
    artifacts: &dyn noir_zk_core::Artifacts,
    member: String,
    envelope: String,
    t: &Transfer,
) -> eyre::Result<emit_circuits::FoldedProof> {
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
        .app(KernelStepDg1Envelope::select("dg1_envelope", envelope).map_err(e("envelope"))?)
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
