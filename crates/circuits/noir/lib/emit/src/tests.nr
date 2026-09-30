//! Parity with the Rust reference (reference/src/bin/gen.rs writes
//! vectors.nr): the same witness gives the same ctx, nullifiers,
//! commitments and note commitment, and the note envelope app seals the
//! note payload as the reference does.

use crate::transfer;
use crate::vectors::{
    CID, COMMITMENTS, CTX, FEE, INS, NOTE_COMMITMENT, NOTE_ENVELOPE, NOTE_PAYLOAD, NOTE_SALT,
    NULLIFIERS, OUTS, PAYOUT, ROOT, S,
};
use channel::payload::envelope;
use channel::ratchet::KEY_NOTE_DOMAIN;

#[test]
fn transfer_matches_reference() {
    let t = transfer(CID, ROOT, 0, 0, FEE, PAYOUT, INS, OUTS, NOTE_SALT);
    assert_eq(t.ctx, CTX);
    assert_eq(t.nullifiers, NULLIFIERS);
    assert_eq(t.commitments, COMMITMENTS);
    assert_eq(t.note_commitment, NOTE_COMMITMENT);
    assert_eq(
        [t.cid, t.root, t.v_in, t.v_out, t.fee, t.payout_recipient],
        [CID, ROOT, 0, 0, FEE, PAYOUT],
    );
}

/// The note envelope app (under the session's chain key S) continues the
/// transfer's link and seals the opening the reference seals.
#[test]
fn note_envelope_matches_reference() {
    let t = transfer(CID, ROOT, 0, 0, FEE, PAYOUT, INS, OUTS, NOTE_SALT);
    let env = envelope(KEY_NOTE_DOMAIN, NOTE_PAYLOAD, NOTE_SALT, CTX, S);
    assert_eq(env[0], t.note_commitment);
    assert_eq(env, NOTE_ENVELOPE);
}

#[test(should_fail_with = "input note is not in the tree")]
fn rejects_wrong_root() {
    let _ = transfer(CID, ROOT + 1, 0, 0, FEE, PAYOUT, INS, OUTS, NOTE_SALT);
}

#[test(should_fail_with = "value is not conserved")]
fn rejects_wrong_fee() {
    let _ = transfer(CID, ROOT, 0, 0, FEE + 1, PAYOUT, INS, OUTS, NOTE_SALT);
}

#[test]
fn transfer_holder_publishes_the_tag_of_its_inputs_key() {
    let min = crate::MIN_NOTE_VALUE as Field;
    let (ins, outs) = holder_notes(min, min);
    let v_in = 2 * min + FEE;
    let t = crate::transfer(CID, ROOT, v_in, 0, FEE, PAYOUT, ins, outs, NOTE_SALT).flatten();
    let r = deposit(min, min);
    assert_eq(r[0], t[0]);
    assert_eq(r[1], crate::holder_tag(ins[0].sk, t[0]));
    for i in 1..12 {
        assert_eq(r[i + 1], t[i]);
    }
}

#[test(should_fail_with = "the inputs have two holders")]
fn transfer_holder_rejects_two_keys() {
    let min = crate::MIN_NOTE_VALUE as Field;
    let (mut ins, outs) = holder_notes(min, 0);
    ins[1].sk = ins[0].sk + 1;
    let _ = crate::transfer_holder(CID, ROOT, min + FEE, 0, FEE, PAYOUT, ins, outs, NOTE_SALT);
}

/// One holder's dummy inputs and outputs worth `a` and `b`.
fn holder_notes(a: Field, b: Field) -> ([crate::InNote; 2], [crate::OutNote; 2]) {
    let mut ins = INS;
    ins[1].sk = ins[0].sk;
    ins[0].value = 0;
    ins[1].value = 0;
    let mut outs = OUTS;
    outs[0].value = a;
    outs[1].value = b;
    (ins, outs)
}

/// A deposit of `a` and `b` into one holder's notes.
fn deposit(a: Field, b: Field) -> [Field; crate::TRANSFER_HOLDER_FIELDS] {
    let (ins, outs) = holder_notes(a, b);
    crate::transfer_holder(CID, ROOT, a + b + FEE, 0, FEE, PAYOUT, ins, outs, NOTE_SALT)
}

#[test]
fn transfer_holder_accepts_the_minimum_and_dummies() {
    let min = crate::MIN_NOTE_VALUE as Field;
    let _ = deposit(min, 0);
    let _ = deposit(min, min + 1);
}

#[test(should_fail_with = "output note below the minimum value")]
fn transfer_holder_rejects_a_note_below_the_minimum() {
    let _ = deposit(
        crate::MIN_NOTE_VALUE as Field,
        crate::MIN_NOTE_VALUE as Field - 1,
    );
}
