//! Emit V2 notes and the 2-in / 2-out JoinSplit transfer with the note opening sealed on the
//! channel, as the transfer app constrains it (from the experiments repository's reference crate).

use crate::tree::{Path, TREE_DEPTH};
use ark_ff::Zero;
use toml::{Table, Value};
use zk_encryption_circuits::wallet::Fr;
use zk_encryption_circuits::wallet::emit::{Emit, NoteOpening};
use zk_encryption_circuits::wallet::poseidon::{FieldHex, Rng};
use zk_encryption_circuits::wallet::ratchet::Ratchet;
use zk_encryption_circuits::wallet::sender::ChannelWitness;

/// A transfer input.
#[derive(Clone, Debug)]
pub struct InNote {
    pub sk: Fr,
    pub value: u128,
    pub rho: Fr,
    pub r: Fr,
    pub path: Path,
}

impl InNote {
    /// A dummy input (value 0, membership skipped) with a fresh unique nullifier.
    pub fn dummy() -> Self {
        Self {
            sk: Rng::field(),
            value: 0,
            rho: Rng::field(),
            r: Fr::zero(),
            path: Path { index: 0, siblings: vec![Fr::zero(); TREE_DEPTH] },
        }
    }
}

#[derive(Clone, Debug)]
pub struct OutNote {
    pub pk: Fr,
    pub value: u128,
    pub r: Fr,
}

impl OutNote {
    pub fn to(pk: Fr, value: u128) -> Self {
        Self { pk, value, r: Rng::field() }
    }
}

/// The witness of one transfer and what it publishes.
#[derive(Clone, Debug)]
pub struct Transfer {
    pub cid: Fr,
    pub root: Fr,
    pub ins: [InNote; 2],
    pub outs: [OutNote; 2],
    pub v_in: u128,
    pub v_out: u128,
    pub fee: u128,
    pub payout: Fr,
    pub channel: ChannelWitness,
    pub nullifiers: [Fr; 2],
    pub commitments: [Fr; 2],
    pub rhos: [Fr; 2],
    pub ctx: Fr,
    pub note_salt: Fr,
}

#[derive(Debug)]
pub enum BuildError {
    ValueNotConserved,
    NotInTree,
    DuplicateNullifier,
}

impl Transfer {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        cid: Fr,
        root: Fr,
        ins: [InNote; 2],
        outs: [OutNote; 2],
        v_in: u128,
        v_out: u128,
        fee: u128,
        payout: Fr,
        channel: ChannelWitness,
    ) -> Result<Self, BuildError> {
        let total_in = ins.iter().map(|n| n.value).sum::<u128>() + v_in;
        let total_out = outs.iter().map(|n| n.value).sum::<u128>() + v_out + fee;
        if total_in != total_out {
            return Err(BuildError::ValueNotConserved);
        }
        for n in ins.iter().filter(|n| n.value != 0) {
            if n.path.root(Emit::commitment(cid, Emit::pk(n.sk), n.value, n.rho, n.r)) != root {
                return Err(BuildError::NotInTree);
            }
        }
        let nullifiers = [0, 1].map(|i| Emit::nullifier(Emit::nk(ins[i].sk), ins[i].rho));
        if nullifiers[0] == nullifiers[1] {
            return Err(BuildError::DuplicateNullifier);
        }
        let rhos = [Emit::rho(nullifiers[0], 0), Emit::rho(nullifiers[0], 1)];
        let commitments =
            [0, 1].map(|j| Emit::commitment(cid, outs[j].pk, outs[j].value, rhos[j], outs[j].r));
        let ctx = Emit::ctx(cid, nullifiers, commitments);
        Ok(Self {
            cid,
            root,
            ins,
            outs,
            v_in,
            v_out,
            fee,
            payout,
            channel,
            nullifiers,
            commitments,
            rhos,
            ctx,
            note_salt: Rng::field(),
        })
    }

    /// Output `j`'s opening.
    pub fn opening(&self, j: usize) -> NoteOpening {
        NoteOpening { value: self.outs[j].value, rho: self.rhos[j], r: self.outs[j].r }
    }

    /// The transfer app's `Prover.toml`: the notes as tables and the note salt.
    pub fn inputs(&self) -> String {
        let s = |f: Fr| Value::String(f.hex());
        let table = |kv: Vec<(&str, Value)>| {
            Value::Table(kv.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
        };
        let note = |n: &InNote| {
            table(vec![
                ("sk", s(n.sk)),
                ("value", s(Fr::from(n.value))),
                ("rho", s(n.rho)),
                ("r", s(n.r)),
                ("index", Value::String(n.path.index.to_string())),
                ("path", Value::Array(n.path.siblings.iter().map(|x| s(*x)).collect())),
            ])
        };
        let out = |o: &OutNote| {
            table(vec![("pk", s(o.pk)), ("value", s(Fr::from(o.value))), ("r", s(o.r))])
        };
        let mut t = Table::new();
        t.insert("cid".into(), s(self.cid));
        t.insert("root".into(), s(self.root));
        t.insert("v_in".into(), s(Fr::from(self.v_in)));
        t.insert("v_out".into(), s(Fr::from(self.v_out)));
        t.insert("fee".into(), s(Fr::from(self.fee)));
        t.insert("payout_recipient".into(), s(self.payout));
        t.insert("ins".into(), Value::Array(self.ins.iter().map(note).collect()));
        t.insert("outs".into(), Value::Array(self.outs.iter().map(out).collect()));
        t.insert("note_salt".into(), s(self.note_salt));
        toml::to_string(&t).expect("toml")
    }

    /// The session app's `Prover.toml`.
    pub fn session_inputs(&self) -> String {
        zk_encryption_circuits::session::inputs(&self.channel, self.ctx)
    }

    /// The note envelope app's `Prover.toml`: output 0's opening under the note domain.
    pub fn note_inputs(&self) -> String {
        zk_encryption_circuits::envelope::inputs(
            Ratchet::key_note(),
            &self.opening(0).to_payload(),
            self.note_salt,
            self.ctx,
            self.channel.s,
        )
    }
}
