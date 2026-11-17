use anyhow::{Result, ensure};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{PreparedVerifyingKey, ProvingKey, VerifyingKey, prepare_verifying_key};
use js_sys::{Function, Uint8Array};
use sha2::{Digest, Sha256};
use std::io::{self, Read};
use wasm_bindgen::prelude::*;

use crate::{engine::{self, Manifest, Session}, fixture::{Fixture, parse_field}};

fn error(value: impl std::fmt::Display) -> JsValue { JsValue::from_str(&value.to_string()) }

/// Reads borrowed JS assets in bounded chunks, never a second full encoded PK.
struct JsReader {
    callback: Function,
    length: u64,
    fetched: u64,
    buffer: Vec<u8>,
    cursor: usize,
    digest: Sha256,
}

impl JsReader {
    fn new(callback: Function, length: u64) -> Self {
        Self { callback, length, fetched: 0, buffer: Vec::new(), cursor: 0, digest: Sha256::new() }
    }
    fn check(self, expected: &str) -> Result<()> {
        ensure!(self.fetched == self.length && self.cursor == self.buffer.len(), "artifact not fully consumed");
        ensure!(hex::encode(self.digest.finalize()) == expected, "artifact SHA-256 mismatch");
        Ok(())
    }
}

impl Read for JsReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() { return Ok(0); }
        if self.cursor == self.buffer.len() {
            if self.fetched == self.length { return Ok(0); }
            let size = (self.length - self.fetched).min(1024 * 1024) as usize;
            let value = self.callback.call2(&JsValue::NULL, &JsValue::from_f64(self.fetched as f64), &JsValue::from_f64(size as f64))
                .map_err(|value| io::Error::other(format!("asset reader failed: {value:?}")))?;
            let chunk = Uint8Array::new(&value);
            if chunk.length() as usize != size { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short JS asset chunk")); }
            self.buffer.resize(size, 0);
            chunk.copy_to(&mut self.buffer);
            self.digest.update(&self.buffer);
            self.cursor = 0;
            self.fetched += size as u64;
        }
        let size = output.len().min(self.buffer.len() - self.cursor);
        output[..size].copy_from_slice(&self.buffer[self.cursor..self.cursor + size]);
        self.cursor += size;
        Ok(size)
    }
}

#[wasm_bindgen]
pub struct WasmSession { session: Session }

#[wasm_bindgen(js_name = loadSession)]
pub fn load_session(fixture_json: &str, manifest_json: &str, pk_reader: Function, pk_length: f64, vk_bytes: &[u8]) -> Result<WasmSession, JsValue> {
    let result = (|| -> Result<WasmSession> {
        let manifest: Manifest = serde_json::from_str(manifest_json)?;
        manifest.validate()?;
        ensure!(pk_length.is_finite() && pk_length >= 0.0 && pk_length.fract() == 0.0 && pk_length as u64 == manifest.stats.prover_key_bytes, "PK length mismatch");
        ensure!(manifest.stats.wasm32_lower_bound_bytes < 4_294_901_760, "wasm32 blocker: decoded queries + two QAP vectors + assignment require {} bytes (4GiB address space; excludes ACVM/FFT/MSM scratch)", manifest.stats.wasm32_lower_bound_bytes);
        ensure!(vk_bytes.len() as u64 == manifest.stats.verifier_key_bytes, "VK length mismatch");
        ensure!(hex::encode(Sha256::digest(vk_bytes)) == manifest.sha256["vk"], "VK SHA-256 mismatch");
        let fixture = Fixture::parse(fixture_json)?.load()?;
        ensure!(manifest.relation_id == fixture.relation_id, "key relation differs from fixture");
        let mut reader = JsReader::new(pk_reader, manifest.stats.prover_key_bytes);
        let pk: ProvingKey<Bn254> = engine::decode(&mut reader)?;
        reader.check(&manifest.sha256["pk"])?;
        let vk: VerifyingKey<Bn254> = engine::decode(vk_bytes)?;
        Ok(WasmSession { session: Session::new(fixture, manifest, pk, vk)? })
    })();
    result.map_err(error)
}

#[wasm_bindgen]
impl WasmSession {
    pub fn prove(&self, plan_reader: Function, plan_length: f64) -> Result<Vec<u8>, JsValue> {
        let result = (|| -> Result<Vec<u8>> {
            ensure!(plan_length.is_finite() && plan_length >= 0.0 && plan_length.fract() == 0.0 && plan_length as u64 == self.session.manifest.stats.matrix_plan_bytes, "R1CS plan length mismatch");
            let mut reader = JsReader::new(plan_reader, self.session.manifest.stats.matrix_plan_bytes);
            let proof = self.session.prove(&mut reader)?;
            reader.check(&self.session.manifest.sha256["r1cs"])?;
            Ok(proof)
        })();
        result.map_err(error)
    }

    pub fn verify(&self, proof: &[u8]) -> Result<bool, JsValue> {
        self.session.verify(proof).map_err(error)
    }

    /// Exposed for negative public-binding checks, never used by adapter verify().
    #[wasm_bindgen(js_name = verifyPublic)]
    pub fn verify_public(&self, proof: &[u8], public_json: &str) -> Result<bool, JsValue> {
        let result = (|| -> Result<bool> {
            let values: Vec<String> = serde_json::from_str(public_json)?;
            let values = values.iter().map(|v| parse_field(v)).collect::<Result<Vec<_>>>()?;
            self.session.verify_public(proof, &values)
        })();
        result.map_err(error)
    }

    #[wasm_bindgen(getter)]
    pub fn stats(&self) -> Result<String, JsValue> { serde_json::to_string(&self.session.manifest.stats).map_err(error) }
}

#[wasm_bindgen]
pub struct WasmVerifier {
    key: PreparedVerifyingKey<Bn254>,
    public: Vec<Fr>,
    stats: String,
}

#[wasm_bindgen(js_name = loadVerifier)]
pub fn load_verifier(fixture_json: &str, manifest_json: &str, vk_bytes: &[u8]) -> Result<WasmVerifier, JsValue> {
    let result = (|| -> Result<WasmVerifier> {
        let manifest: Manifest = serde_json::from_str(manifest_json)?;
        manifest.validate()?;
        ensure!(vk_bytes.len() as u64 == manifest.stats.verifier_key_bytes, "VK length mismatch");
        ensure!(hex::encode(Sha256::digest(vk_bytes)) == manifest.sha256["vk"], "VK SHA-256 mismatch");
        let fixture = Fixture::parse(fixture_json)?;
        ensure!(manifest.pipeline == fixture.pipeline && manifest.relation_id == fixture.relation_id()?, "key relation differs from fixture");
        let public = fixture.expected_public.iter().map(|v| parse_field(v)).collect::<Result<Vec<_>>>()?;
        let vk: VerifyingKey<Bn254> = engine::decode(vk_bytes)?;
        ensure!(vk.gamma_abc_g1.len() == public.len() + 1, "public key arity differs");
        Ok(WasmVerifier {
            key: prepare_verifying_key(&vk), public,
            stats: serde_json::to_string(&manifest.stats)?,
        })
    })();
    result.map_err(error)
}

#[wasm_bindgen]
impl WasmVerifier {
    pub fn verify(&self, proof: &[u8]) -> Result<bool, JsValue> {
        engine::verify(&self.key, proof, &self.public).map_err(error)
    }

    #[wasm_bindgen(js_name = verifyPublic)]
    pub fn verify_public(&self, proof: &[u8], public_json: &str) -> Result<bool, JsValue> {
        let result = (|| -> Result<bool> {
            let public: Vec<String> = serde_json::from_str(public_json)?;
            let public = public.iter().map(|v| parse_field(v)).collect::<Result<Vec<_>>>()?;
            engine::verify(&self.key, proof, &public)
        })();
        result.map_err(error)
    }

    #[wasm_bindgen(getter)]
    pub fn stats(&self) -> String { self.stats.clone() }
}

#[wasm_bindgen(js_name = uncompressProof)]
pub fn uncompress_proof(bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    use ark_serialize::CanonicalSerialize;
    let result = (|| -> Result<Vec<u8>> {
        let proof: ark_groth16::Proof<Bn254> = engine::decode(bytes)?;
        let mut output = Vec::with_capacity(proof.uncompressed_size());
        proof.serialize_uncompressed(&mut output)?;
        Ok(output)
    })();
    result.map_err(error)
}

#[wasm_bindgen(js_name = threadCount)]
pub fn thread_count() -> usize {
    #[cfg(feature = "parallel")]
    { rayon::current_num_threads() }
    #[cfg(not(feature = "parallel"))]
    { 1 }
}
