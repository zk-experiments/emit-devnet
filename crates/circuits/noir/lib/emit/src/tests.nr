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
