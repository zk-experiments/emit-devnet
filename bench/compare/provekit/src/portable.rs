//! Native64-compatible SHA-256 transcript for both host and wasm32.
//!
//! provekit-spongefish 0.2.0 instantiations/hash.rs absorbs two `usize`
//! counters as big-endian bytes. Those are 8 bytes on native64 but 4 on
//! wasm32. Fix their wire width to u64; all domain masks and transitions
//! match the pinned upstream sponge, without changing native proof bytes.
use ark_bn254::Fr;
use provekit_common::{FieldHash, HashConfig, ProofField};
use sha2::{Digest, Sha256};
use whir::{algebra::embedding::Identity, transcript::DuplexSpongeInterface};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortableBn254;

impl ProofField for PortableBn254 {
    type Embedding = Identity<Fr>;
    const FIELD_ID: u8 = 0;
}

impl FieldHash for PortableBn254 {
    fn register() { provekit_backend_bn254::register(); }
    fn hash_public_inputs(config: HashConfig, inputs: &[Fr]) -> Fr {
        provekit_backend_bn254::Bn254Field::hash_public_inputs(config, inputs)
    }
    fn ext_to_bytes_le(value: &Fr) -> Vec<u8> {
        provekit_backend_bn254::Bn254Field::ext_to_bytes_le(value)
    }
    type Sponge = PortableSha256;
    fn transcript_sponge(config: HashConfig) -> Self::Sponge { PortableSha256::from_config(config) }
}

#[derive(Clone, Copy)]
enum Mode { Start, Absorb, Squeeze(u64) }

#[derive(Clone)]
pub struct PortableSha256 {
    hasher: Sha256,
    cv: [u8; 32],
    mode: Mode,
    block: [u8; 32],
    cursor: usize,
}

impl Default for PortableSha256 {
    fn default() -> Self {
        Self { hasher: Sha256::new(), cv: [0; 32], mode: Mode::Start, block: [0; 32], cursor: 32 }
    }
}

impl PortableSha256 {
    pub fn from_config(config: HashConfig) -> Self {
        assert!(matches!(config, HashConfig::Sha256), "Portable comparison transcript requires SHA-256");
        Self::default()
    }
    fn mask(tag: u8) -> [u8; 64] {
        let mut mask = [0; 64];
        mask[63] = tag;
        mask
    }
    fn squeeze_end(&mut self) {
        if let Mode::Squeeze(blocks) = self.mode {
            let bytes = blocks * 32 - (32 - self.cursor) as u64;
            let mut hasher = Sha256::new();
            hasher.update(Self::mask(2));
            hasher.update(self.cv);
            hasher.update(bytes.to_be_bytes());
            self.cv = hasher.finalize().into();
            self.hasher = Sha256::new();
            self.mode = Mode::Start;
            self.cursor = 32;
        }
    }
}

impl DuplexSpongeInterface for PortableSha256 {
    type U = u8;
    fn absorb(&mut self, input: &[u8]) -> &mut Self {
        self.squeeze_end();
        if matches!(self.mode, Mode::Start) {
            self.mode = Mode::Absorb;
            self.hasher.update(Self::mask(0));
            self.hasher.update(self.cv);
        }
        self.hasher.update(input);
        self
    }
    fn ratchet(&mut self) -> &mut Self {
        self.squeeze_end();
        let digest = std::mem::take(&mut self.hasher).finalize();
        self.cv = Sha256::digest(digest).into();
        self.mode = Mode::Start;
        self.cursor = 32;
        self
    }
    fn squeeze(&mut self, mut output: &mut [u8]) -> &mut Self {
        if matches!(self.mode, Mode::Absorb) { self.ratchet(); }
        if matches!(self.mode, Mode::Start) {
            self.mode = Mode::Squeeze(0);
            self.hasher.update(Self::mask(1));
            self.hasher.update(self.cv);
        }
        while !output.is_empty() {
            if self.cursor == 32 {
                let Mode::Squeeze(index) = self.mode else { unreachable!() };
                let mut hasher = self.hasher.clone();
                hasher.update(index.to_be_bytes());
                self.block = hasher.finalize().into();
                self.cursor = 0;
                self.mode = Mode::Squeeze(index + 1);
            }
            let length = output.len().min(32 - self.cursor);
            output[..length].copy_from_slice(&self.block[self.cursor..self.cursor + length]);
            self.cursor += length;
            output = &mut output[length..];
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_native64_golden_vector_on_every_target() {
        // Published provekit-spongefish0.2.0 test_shosha 65-byte vector.
        let expected = hex::decode("ebe4ef29e18aa54137edd89c23f8bfeac2731c9f675da20e7c67d5ad68d7ee2d40a45232b599552d46b520082fb2705971f07b3158b072b63ab0934a05e6af6448").unwrap();
        let mut sponge = PortableSha256::default();
        sponge.absorb(b"asd").ratchet().absorb(b"asdasd");
        let mut bytes = [0; 65];
        sponge.squeeze(&mut bytes[..1]).squeeze(&mut bytes[1..32]).squeeze(&mut bytes[32..]);
        assert_eq!(bytes.as_slice(), expected);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn native64_parity_including_squeeze_end_and_ratchets() {
        let mut portable = PortableSha256::default();
        let mut upstream = provekit_backend_bn254::TranscriptSponge::from_config(HashConfig::Sha256);
        for length in [0, 1, 31, 32, 33, 63, 64, 65, 129] {
            portable.absorb(b"cross-runtime");
            upstream.absorb(b"cross-runtime");
            let mut left = [0; 129];
            let mut right = [0; 129];
            portable.squeeze(&mut left[..length]);
            upstream.squeeze(&mut right[..length]);
            assert_eq!(left, right);
            // This absorb exercises the second formerly usize-sized counter.
            portable.absorb(b"after-squeeze").squeeze(&mut left).ratchet();
            upstream.absorb(b"after-squeeze").squeeze(&mut right).ratchet();
            assert_eq!(left, right);
        }
    }
}
