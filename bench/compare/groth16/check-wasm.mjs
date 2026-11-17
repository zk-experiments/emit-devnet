#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { prepare, prepareVerifier } from '../groth16.mjs';

const [mode, fixturePath, keyDirectory, proofPath, threadText = '1'] = process.argv.slice(2);
if (!['prove', 'verify'].includes(mode) || !fixturePath || !keyDirectory || !proofPath) throw new Error('Usage: node check-wasm.mjs prove|verify FIXTURE KEY_DIR PROOF_BIN [THREADS=1]');
const threads = Number(threadText);
const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
const manifest = await readFile(path.join(keyDirectory, 'manifest.json'));
const metadata = JSON.parse(manifest.toString('utf8'));
const assets = {
  manifest,
  vk: await readFile(path.join(keyDirectory, metadata.files.vk)),
  wasm: await readFile(new URL(`./pkg-${threads > 1 ? 'threads' : 'single'}/passport_groth16_bg.wasm`, import.meta.url)),
};
if (mode === 'prove') {
  assets.pk = await readFile(path.join(keyDirectory, metadata.files.pk));
  assets.r1cs = await readFile(path.join(keyDirectory, metadata.files.r1cs));
}
const session = await (mode === 'prove' ? prepare : prepareVerifier)({ fixture, assets, threads });
try {
  assert.equal(session.stats.threads, threads);
  const proof = mode === 'prove' ? await session.prove() : await readFile(proofPath);
  assert.equal(await session.verify(proof), true);
  assert.equal(session.proofBytes(proof).byteLength, 128);
  assert.equal(session.uncompressedProofBytes(proof).byteLength, 256);
  for (let index = 0; index < fixture.expected_public.length; index++) {
    const changed = [...fixture.expected_public];
    changed[index] = `0x${(BigInt(changed[index]) === 0n ? 1n : 0n).toString(16).padStart(64, '0')}`;
    assert.equal(await session.verifyPublic(proof, changed), false, `public field ${index}`);
  }
  assert.equal(await session.verifyPublic(proof, fixture.expected_public.slice(1)), false);
  assert.equal(await session.verify(proof.subarray(0, proof.length - 1)), false);
  const corrupted = Uint8Array.from(proof);
  corrupted[0] ^= 1;
  assert.equal(await session.verify(corrupted), false);
  const trailing = new Uint8Array(proof.length + 1);
  trailing.set(proof);
  assert.equal(await session.verify(trailing), false);
  if (mode === 'prove') await writeFile(proofPath, proof);
  console.log(JSON.stringify({ mode, verified: true, proof_bytes: proof.length, uncompressed_proof_bytes: session.uncompressedProofBytes(proof).length, stats: session.stats }));
} finally {
  await session.dispose();
}
