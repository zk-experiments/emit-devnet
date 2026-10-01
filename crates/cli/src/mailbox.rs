//! The devnet's stand-in for the delivery layer: the off-chain envelope of a transfer
//! (`emit_protocol::Envelope`: the lattice ciphertext and the sealed DG1, which the chain no longer
//! carries; it sees only `env_commit`) travels through a directory the wallets share, one file per
//! chain commitment C_t. The sender writes it before broadcasting and whichever wallet sees the
//! escrow close deletes it. Outside the devnet the envelope-inbox service plays this part.

use emit_protocol::Envelope;
use std::path::{Path, PathBuf};
use zk_encryption_circuits::wallet::Fr;
use zk_encryption_circuits::wallet::poseidon::FieldHex;

fn path(home: &Path, c_t: Fr) -> PathBuf {
    home.join("mailbox").join(format!("{}.bin", c_t.hex()))
}

pub fn put(home: &Path, c_t: Fr, envelope: &Envelope) -> eyre::Result<()> {
    let p = path(home, c_t);
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(p, envelope.as_bytes())?;
    Ok(())
}

/// The envelope under `c_t`, if one was delivered.
pub fn get(home: &Path, c_t: Fr) -> eyre::Result<Option<Envelope>> {
    match std::fs::read(path(home, c_t)) {
        Ok(b) => Envelope::from_slice(&b)
            .map(Some)
            .map_err(|e| eyre::eyre!("mailbox: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Deletes the envelope under `c_t` (gone already is fine).
pub fn remove(home: &Path, c_t: Fr) {
    let _ = std::fs::remove_file(path(home, c_t));
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_encryption_circuits::wallet::lattice::Ciphertext;

    #[test]
    fn round_trips_through_the_directory() {
        let envelope = Envelope::from_parts(
            &Ciphertext {
                u: [[7u16; 256]; 3],
                v: [9u16; 256],
            },
            &[1u64, 2, 3, 4, 5, 6].map(Fr::from),
        );
        let home = std::env::temp_dir().join(format!("zkpool-mailbox-{}", std::process::id()));
        let c_t = Fr::from(42u64);
        assert!(get(&home, c_t).expect("readable").is_none());
        put(&home, c_t, &envelope).expect("written");
        assert_eq!(get(&home, c_t).expect("readable"), Some(envelope));
        remove(&home, c_t);
        assert!(get(&home, c_t).expect("readable").is_none());
        let _ = std::fs::remove_dir_all(home);
    }
}
