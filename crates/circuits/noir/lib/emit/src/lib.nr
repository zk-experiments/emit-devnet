//! Emit V2 private transfer (2-in / 2-out JoinSplit, shielded keys), with
//! the note opening for the recipient committed to as a channel payload for
//! the note envelope app to seal. The channel itself (the KEM, C_t) is the
//! session app's (channel::session). Reference: reference/src/emit.rs.
//! Specification: README.md.

mod tests;
mod vectors;

use channel::payload::commit;
use poseidon::poseidon2::Poseidon2;

/// Domain tags ("emit-v2/<label>") as big-endian integers.
pub global NK: Field = 0x656d69742d76322f6e6b;
pub global PK: Field = 0x656d69742d76322f706b;
pub global NULLIFIER: Field = 0x656d69742d76322f6e756c6c6966696572;
pub global COMMITMENT: Field = 0x656d69742d76322f636f6d6d69746d656e74;
pub global RHO: Field = 0x656d69742d76322f72686f;
pub global CTX: Field = 0x656d69742d76322f637478;

pub global TREE_DEPTH: u32 = 32;
/// Values are single fields range-checked to 128 bits.
pub global VALUE_BITS: u32 = 128;

/// Transfer's databus output (`Transfer::flatten`): 11 public fields, then
/// the note payload's commitment (the link to the note envelope app).
pub global TRANSFER_FIELDS: u32 = 12;

fn h<let N: u32>(x: [Field; N]) -> Field {
    Poseidon2::hash(x, N)
}

pub fn commitment(cid: Field, pk: Field, value: Field, rho: Field, r: Field) -> Field {
    h([COMMITMENT, cid, pk, value, rho, r])
}

/// Depth-32 Poseidon2 Merkle root: node = H(left, right).
pub fn merkle_root(leaf: Field, index: Field, path: [Field; TREE_DEPTH]) -> Field {
    let bits: [bool; TREE_DEPTH] = index.to_le_bits();
    let mut node = leaf;
    for l in 0..TREE_DEPTH {
        node = if bits[l] {
            h([path[l], node])
        } else {
            h([node, path[l]])
        };
    }
    node
}

/// A note being spent. `value = 0` marks a dummy input (deposits), which
/// skips the membership check but still needs a unique nullifier.
pub struct InNote {
    pub sk: Field,
    pub value: Field,
    pub rho: Field,
    pub r: Field,
    pub index: Field,
    pub path: [Field; TREE_DEPTH],
}

/// A note being created for `pk`; its rho is derived from the first nullifier.
pub struct OutNote {
    pub pk: Field,
    pub value: Field,
    pub r: Field,
}

pub struct Transfer {
    pub ctx: Field,
    pub cid: Field,
    pub root: Field,
    pub nullifiers: [Field; 2],
    pub commitments: [Field; 2],
    pub v_in: Field,
    pub v_out: Field,
    pub fee: Field,
    pub payout_recipient: Field,
    pub note_commitment: Field,
}

impl Transfer {
    /// `[ctx, cid, root, N0, N1, C0, C1, v_in, v_out, fee, payout_recipient, note_commitment]`.
    pub fn flatten(self) -> [Field; TRANSFER_FIELDS] {
        [
            self.ctx,
            self.cid,
            self.root,
            self.nullifiers[0],
            self.nullifiers[1],
            self.commitments[0],
            self.commitments[1],
            self.v_in,
            self.v_out,
            self.fee,
            self.payout_recipient,
            self.note_commitment,
        ]
    }
}

/// The JoinSplit: returns (nullifiers, commitments, output rhos, ctx).
/// - inputs: C = H(COMMITMENT, cid, H(PK, sk), value, rho, r) is in the tree
///   under `root` unless value = 0; N = H(NULLIFIER, H(NK, sk), rho); N0 ≠ N1;
/// - outputs: rho'_j = H(RHO, N0, j), C'_j = H(COMMITMENT, cid, pk_j, v'_j, rho'_j, r'_j);
/// - v0 + v1 + v_in = v'0 + v'1 + v_out + fee, every value < 2^128;
/// - ctx = H(CTX, cid, N0, N1, C'0, C'1).
pub fn joinsplit(
    cid: Field,
    root: Field,
    v_in: Field,
    v_out: Field,
    fee: Field,
    ins: [InNote; 2],
    outs: [OutNote; 2],
) -> ([Field; 2], [Field; 2], [Field; 2], Field) {
    let mut nullifiers: [Field; 2] = [0; 2];
    let mut total_in = v_in;
    v_in.assert_max_bit_size::<VALUE_BITS>();
    for i in 0..2 {
        let n = ins[i];
        n.value.assert_max_bit_size::<VALUE_BITS>();
        let c = commitment(cid, h([PK, n.sk]), n.value, n.rho, n.r);
        let member = merkle_root(c, n.index, n.path) == root;
        assert(member | (n.value == 0), "input note is not in the tree");
        nullifiers[i] = h([NULLIFIER, h([NK, n.sk]), n.rho]);
        total_in += n.value;
    }
    assert(nullifiers[0] != nullifiers[1], "input nullifiers must differ");

    let mut commitments: [Field; 2] = [0; 2];
    let mut rhos: [Field; 2] = [0; 2];
    let mut total_out = v_out + fee;
    v_out.assert_max_bit_size::<VALUE_BITS>();
    fee.assert_max_bit_size::<VALUE_BITS>();
    for j in 0..2 {
        let o = outs[j];
        o.value.assert_max_bit_size::<VALUE_BITS>();
        rhos[j] = h([RHO, nullifiers[0], j as Field]);
        commitments[j] = commitment(cid, o.pk, o.value, rhos[j], o.r);
        total_out += o.value;
    }
    assert(total_in == total_out, "value is not conserved");
    let ctx = h(
        [CTX, cid, nullifiers[0], nullifiers[1], commitments[0], commitments[1]],
    );
    (nullifiers, commitments, rhos, ctx)
}

/// The transfer: the JoinSplit, with the opening of C'0 for pk_0's owner as
/// the payload (v'0, rho'0, r'0, 0, 0, 0), committed with `note_salt` for the
/// note envelope app (which seals it under KEY_NOTE on the session's chain
/// key). `payout_recipient` is published as it is.
pub fn transfer(
    cid: Field,
    root: Field,
    v_in: Field,
    v_out: Field,
    fee: Field,
    payout_recipient: Field,
    ins: [InNote; 2],
    outs: [OutNote; 2],
    note_salt: Field,
) -> Transfer {
    let (nullifiers, commitments, rhos, ctx) = joinsplit(cid, root, v_in, v_out, fee, ins, outs);
    Transfer {
        ctx,
        cid,
        root,
        nullifiers,
        commitments,
        v_in,
        v_out,
        fee,
        payout_recipient,
        note_commitment: commit(note_salt, [outs[0].value, rhos[0], outs[0].r, 0, 0, 0]),
    }
}
