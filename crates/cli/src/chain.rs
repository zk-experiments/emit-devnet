//! The pool contract as the wallet sees it: its ABI (contracts/src/EmitV2Pool.sol), the transact
//! call, and its logs grouped per transaction.

use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, Log};
use alloy::sol_types::SolEvent;
use zk_encryption_circuits::wallet::Fr;
use zk_encryption_circuits::wallet::emit::{Envelope, Kem};
use zk_encryption_circuits::wallet::grumpkin::Point;
use zk_encryption_circuits::wallet::lattice::Ciphertext;

alloy::sol! {
    #[sol(rpc)]
    contract EmitV2Pool {
        event NewNullifier(bytes32 nullifier);
        event NewCommitment(bytes32 commitment, uint256 leafIndex);
        event Envelope(bytes32 cT, bytes32[2] e, bytes32 tag, bytes32 ct, bytes pqCiphertext, bytes32[6] cNote, bytes32[6] cId);

        function transact(bytes32 root, bytes32[2] nullifiers, bytes32[2] commitments, uint256 vPubIn, uint256 vPubOut, uint256 fee, address payout, bytes pqCiphertext, bytes proof) external payable;
        function currentRoot() external view returns (uint256);
        function nextIndex() external view returns (uint256);
    }
}

pub fn b256(f: &Fr) -> B256 {
    use zk_encryption_circuits::wallet::poseidon::FieldHex;
    B256::from(f.to_be32())
}

pub fn fr(b: &B256) -> Fr {
    use ark_ff::PrimeField;
    Fr::from_be_bytes_mod_order(b.as_slice())
}

/// One pool transaction's events, in log order.
#[derive(Debug, Default)]
pub struct TxEvents {
    pub tx: B256,
    pub block: u64,
    pub nullifiers: Vec<Fr>,
    pub commitments: Vec<(Fr, u64)>,
    pub envelope: Option<Envelope>,
}

fn envelope(e: &EmitV2Pool::Envelope) -> eyre::Result<Envelope> {
    let f = |b: &B256| fr(b);
    let ct = Ciphertext::from_bytes(&e.pqCiphertext)
        .map_err(|e| eyre::eyre!("Envelope: pqCiphertext: {e:?}"))?;
    Ok(Envelope {
        c_t: f(&e.cT),
        kem: Kem {
            ephemeral: Point { x: f(&e.e[0]), y: f(&e.e[1]) },
            tag: f(&e.tag),
            ct_commitment: f(&e.ct),
            ct,
        },
        c_note: e.cNote.map(|b| fr(&b)),
        c_id: e.cId.map(|b| fr(&b)),
    })
}

/// The pool's events in blocks `from..=to`, grouped by transaction.
pub async fn events(
    p: &impl Provider,
    pool: Address,
    from: u64,
    to: u64,
) -> eyre::Result<Vec<TxEvents>> {
    let logs: Vec<Log> = p
        .get_logs(&Filter::new().address(pool).from_block(from).to_block(to))
        .await?;
    let mut out: Vec<TxEvents> = vec![];
    for log in logs {
        let tx = log.transaction_hash.unwrap_or_default();
        if out.last().is_none_or(|t| t.tx != tx) {
            out.push(TxEvents { tx, block: log.block_number.unwrap_or_default(), ..Default::default() });
        }
        let t = out.last_mut().expect("pushed");
        match log.topic0() {
            Some(&EmitV2Pool::NewNullifier::SIGNATURE_HASH) => {
                let e = log.log_decode::<EmitV2Pool::NewNullifier>()?.inner.data;
                t.nullifiers.push(fr(&e.nullifier));
            }
            Some(&EmitV2Pool::NewCommitment::SIGNATURE_HASH) => {
                let e = log.log_decode::<EmitV2Pool::NewCommitment>()?.inner.data;
                t.commitments.push((fr(&e.commitment), e.leafIndex.to::<u64>()));
            }
            Some(&EmitV2Pool::Envelope::SIGNATURE_HASH) => {
                let e = log.log_decode::<EmitV2Pool::Envelope>()?.inner.data;
                t.envelope = Some(envelope(&e)?);
            }
            _ => {}
        }
    }
    Ok(out)
}

/// The calldata of a transfer and its proof.
pub struct Transact {
    pub root: Fr,
    pub nullifiers: [Fr; 2],
    pub commitments: [Fr; 2],
    pub v_in: u128,
    pub v_out: u128,
    pub fee: u128,
    pub payout: Address,
    pub pq_ciphertext: Vec<u8>,
    pub proof: Vec<u8>,
}

pub struct Sent {
    pub tx: B256,
    pub block: u64,
    pub gas_used: u64,
    pub calldata: usize,
}

pub async fn transact(p: &impl Provider, pool: Address, t: Transact) -> eyre::Result<Sent> {
    let c = EmitV2Pool::new(pool, p);
    let call = c
        .transact(
            b256(&t.root),
            t.nullifiers.map(|n| b256(&n)),
            t.commitments.map(|n| b256(&n)),
            U256::from(t.v_in),
            U256::from(t.v_out),
            U256::from(t.fee),
            t.payout,
            Bytes::from(t.pq_ciphertext),
            Bytes::from(t.proof),
        )
        .value(U256::from(t.v_in));
    let calldata = call.calldata().len();
    let receipt = call
        .send()
        .await
        .map_err(|e| eyre::eyre!("transact refused: {e}"))?
        .get_receipt()
        .await?;
    if !receipt.status() {
        eyre::bail!("transact reverted in {}", receipt.transaction_hash);
    }
    Ok(Sent {
        tx: receipt.transaction_hash,
        block: receipt.block_number.unwrap_or_default(),
        gas_used: receipt.gas_used,
        calldata,
    })
}
