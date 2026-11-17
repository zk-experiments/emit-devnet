import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { join, resolve } from 'node:path';
import { prepare, prepareVerifier, runtimeFiles } from '../provekit.mjs';

const [fixturePath, artifactDirectory, count = '1', nativePath] = process.argv.slice(2);
if (!fixturePath || !artifactDirectory) throw new Error('Usage: node check.mjs FIXTURE ARTIFACT_DIR [1|6] [NATIVE_BINARY]');
const threads = Number(count);
const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
const assets = {
  manifest: new Uint8Array(await readFile(join(artifactDirectory, 'manifest.json'))),
  r1cs: new Uint8Array(await readFile(join(artifactDirectory, 'r1cs.bin'))),
  wasm: new Uint8Array(await readFile(runtimeFiles(threads).wasm)),
};
const started = performance.now();
const session = await prepare({ fixture, assets, threads });
const initialized = performance.now();
assert.equal(session.threads, threads);
const proof = await session.prove();
const proved = performance.now();
assert.equal(await session.verify(proof), true);
const verified = performance.now();
const corrupt = proof.slice();
corrupt[0] ^= 1;
assert.equal(await session.verify(corrupt), false, 'Corrupt proof accepted');
assert.equal(await session.verify(proof.subarray(0, proof.length - 1)), false, 'Truncated proof accepted');
const appended = new Uint8Array(proof.length + 1);
appended.set(proof);
assert.equal(await session.verify(appended), false, 'Trailing proof bytes accepted');

// Change the claimed public field while retaining the exact R1CS/scheme.
// Rebind the *fixture metadata* only, so rejection must come from the crypto
// verifier rather than from the artifact/fixture integrity check.
const wrong = structuredClone(fixture);
const changed = '0x' + (BigInt(wrong.expected_public[0]) ^ 1n).toString(16).padStart(64, '0');
wrong.expected_public[0] = changed;
const [app, output] = wrong.public_outputs[0];
wrong.apps[app].expected_outputs[output] = changed;
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}
const manifestText = new TextDecoder().decode(assets.manifest);
const wrongDigest = createHash('sha256').update(JSON.stringify(canonical(wrong))).digest('hex');
// Preserve native u64/f64 scheme literals; a JS JSON roundtrip loses u64 precision.
assert.equal((manifestText.match(/"fixture_sha256"\s*:/g) ?? []).length, 1);
const wrongManifest = manifestText.replace(/"fixture_sha256"\s*:\s*"[a-f0-9]{64}"/, `"fixture_sha256":"${wrongDigest}"`);
const stats = session.stats;
const proofBytes = session.proofBytes(proof).length;
session.dispose();
const wrongSession = await prepareVerifier({ fixture: wrong, assets: { ...assets,
  manifest: new TextEncoder().encode(wrongManifest) }, threads });
assert.equal(await wrongSession.verify(proof), false, 'Wrong public statement accepted');
wrongSession.dispose();
const verifier = await prepareVerifier({ fixture, assets, threads });
assert.equal(await verifier.verify(proof), true, 'Verification-only path rejected valid proof');
assert.equal(await verifier.verify(corrupt), false, 'Verification-only path accepted corrupt proof');
verifier.dispose();
const proofPath = resolve(artifactDirectory, `proof-wasm-${threads}.bin`);
await writeFile(proofPath, proof);
if (nativePath) {
  const result = spawnSync(resolve(nativePath), ['verify-once', resolve(fixturePath), resolve(artifactDirectory), proofPath, count], { encoding: 'utf8' });
  assert.equal(result.status, 0, `Native verification failed: ${result.stderr}`);
}
console.log(JSON.stringify({ backend: 'provekit', pipeline: fixture.pipeline, threads,
  initialization_ms: initialized - started, prove_ms: proved - initialized,
  verify_ms: verified - proved, proof_bytes: proofBytes,
  stats, tampering_rejected: true, native_verified: Boolean(nativePath), verification_only_checked: true }));
