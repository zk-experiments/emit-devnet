//! The pool contract as the wallet sees it: emit-protocol-abi's `EmitV2Pool`, its deploy, the
//! transact, resolve and refund calls, and its logs grouped per transaction.

use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, Log};
use alloy::sol_types::SolEvent;
use emit_protocol::{Envelope as Sealed, EscrowLog};
pub use emit_protocol_abi::EmitV2Pool;
use zk_encryption_circuits::wallet::Fr;
use zk_encryption_circuits::wallet::emit::{Envelope, Kem};
use zk_encryption_circuits::wallet::grumpkin::Point;

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
    /// Leaves appended: (commitment, leaf index).
    pub commitments: Vec<(Fr, u64)>,
    pub envelope: Option<EnvelopeEvent>,
    /// The escrow events (`Escrowed`, `EscrowClosed`), in log order.
    pub escrow: Vec<EscrowLog>,
    /// Identity cache registrations: (leaf, index, expiry).
    pub identities: Vec<(Fr, u64, u64)>,
}

/// The `Envelope` event: the session's public outputs and the sealed note opening. The lattice
/// ciphertext and the sealed DG1 come off-chain, in the protocol's envelope.
#[derive(Clone, Debug)]
pub struct EnvelopeEvent {
    pub c_t: Fr,
    pub ephemeral: Point,
    pub tag: Fr,
    pub ct_commitment: Fr,
    pub c_note: [Fr; 6],
}

impl EnvelopeEvent {
    /// The channel's `Envelope` (what the receiver scans), with the off-chain part.
    pub fn with(&self, sealed: &Sealed) -> eyre::Result<Envelope> {
        Ok(Envelope {
            c_t: self.c_t,
            kem: Kem {
                ephemeral: self.ephemeral,
                tag: self.tag,
                ct_commitment: self.ct_commitment,
                ct: sealed.ciphertext()?,
            },
            c_note: self.c_note,
            c_id: sealed.c_id()?,
        })
    }
}

fn envelope(e: &EmitV2Pool::Envelope) -> EnvelopeEvent {
    EnvelopeEvent {
        c_t: fr(&e.cT),
        ephemeral: Point {
            x: fr(&e.e[0]),
            y: fr(&e.e[1]),
        },
        tag: fr(&e.tag),
        ct_commitment: fr(&e.ct),
        c_note: e.cNote.map(|b| fr(&b)),
    }
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
            out.push(TxEvents {
                tx,
                block: log.block_number.unwrap_or_default(),
                ..Default::default()
            });
        }
        let t = out.last_mut().expect("pushed");
        match log.topic0() {
            Some(&EmitV2Pool::NewNullifier::SIGNATURE_HASH) => {
                let e = log.log_decode::<EmitV2Pool::NewNullifier>()?.inner.data;
                t.nullifiers.push(fr(&e.nullifier));
            }
            Some(&EmitV2Pool::NewCommitment::SIGNATURE_HASH) => {
                let e = log.log_decode::<EmitV2Pool::NewCommitment>()?.inner.data;
                t.commitments
                    .push((fr(&e.commitment), e.leafIndex.to::<u64>()));
            }
            Some(&EmitV2Pool::Envelope::SIGNATURE_HASH) => {
                let e = log.log_decode::<EmitV2Pool::Envelope>()?.inner.data;
                t.envelope = Some(envelope(&e));
            }
            Some(&EmitV2Pool::Escrowed::SIGNATURE_HASH)
            | Some(&EmitV2Pool::EscrowClosed::SIGNATURE_HASH) => {
                t.escrow.extend(emit_protocol_abi::escrow_log(&log)?);
            }
            Some(&EmitV2Pool::IdentityRegistered::SIGNATURE_HASH) => {
                let e = log
                    .log_decode::<EmitV2Pool::IdentityRegistered>()?
                    .inner
                    .data;
                t.identities
                    .push((fr(&e.leaf), e.index.to::<u64>(), e.expiry.to::<u64>()));
            }
            _ => {}
        }
    }
    Ok(out)
}

/// The calldata of a transfer and its proof.
pub struct Transact {
    /// member_transfer's root.
    pub pipeline: [u8; 32],
    pub root: Fr,
    pub nullifiers: [Fr; 2],
    pub commitments: [Fr; 2],
    pub v_in: u128,
    pub v_out: u128,
    pub fee: u128,
    pub payout: Address,
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
            B256::from(t.pipeline),
            b256(&t.root),
            t.nullifiers.map(|n| b256(&n)),
            t.commitments.map(|n| b256(&n)),
            U256::from(t.v_in),
            U256::from(t.v_out),
            U256::from(t.fee),
            t.payout,
            Bytes::from(t.proof),
        )
        .value(U256::from(t.v_in));
    send(call).await
}

/// Resolves an escrow with a member_resolve proof.
pub async fn resolve(p: &impl Provider, pool: Address, proof: Vec<u8>) -> eyre::Result<Sent> {
    send(EmitV2Pool::new(pool, p).resolve(Bytes::from(proof))).await
}

/// Hands an escrow whose window passed back to its sender.
pub async fn refund(p: &impl Provider, pool: Address, c0: Fr) -> eyre::Result<Sent> {
    send(EmitV2Pool::new(pool, p).refund(b256(&c0))).await
}

/// Registers in the identity cache with an identity_register proof.
pub async fn register(p: &impl Provider, pool: Address, proof: Vec<u8>) -> eyre::Result<Sent> {
    send(EmitV2Pool::new(pool, p).register(Bytes::from(proof))).await
}

async fn send<P: Provider, D: alloy::contract::CallDecoder>(
    call: alloy::contract::CallBuilder<P, D>,
) -> eyre::Result<Sent> {
    let calldata = call.calldata().len();
    // The estimate runs against the pending block, whose producer may differ from the one that
    // includes the transaction (paying the fee to a fresh coinbase costs 25,000 more): pad it.
    let estimate = call
        .estimate_gas()
        .await
        .map_err(|e| eyre::eyre!("refused: {e}"))?;
    let receipt = call
        .gas(estimate + estimate / 5)
        .send()
        .await
        .map_err(|e| eyre::eyre!("refused: {e}"))?
        .get_receipt()
        .await?;
    if !receipt.status() {
        eyre::bail!("reverted in {}", receipt.transaction_hash);
    }
    Ok(Sent {
        tx: receipt.transaction_hash,
        block: receipt.block_number.unwrap_or_default(),
        gas_used: receipt.gas_used,
        calldata,
    })
}
