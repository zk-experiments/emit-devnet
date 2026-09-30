//! The Emit V2 transfer of the `member_transfer` pipeline as a Chonk app: the transfer with both
//! inputs held by one key and that key's holder tag in the transfer's ctx
//! (`emit::transfer_holder`): `[ctx, holder_tag, cid, root, N0, N1, C0, C1, v_in, v_out, fee,
//! payout_recipient, note_commitment]`.
use emit::{InNote, OutNote, transfer_holder, TRANSFER_HOLDER_FIELDS};

fn main(
    cid: Field,
    root: Field,
    v_in: Field,
    v_out: Field,
    fee: Field,
    payout_recipient: Field,
    ins: [InNote; 2],
    outs: [OutNote; 2],
    note_salt: Field,
) -> return_data [Field; TRANSFER_HOLDER_FIELDS] {
    transfer_holder(
        cid,
        root,
        v_in,
        v_out,
        fee,
        payout_recipient,
        ins,
        outs,
        note_salt,
    )
}
