#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { copyFile, readdir, writeFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { ensureArkEc } from './vendor.mjs';

const root = fileURLToPath(new URL('.', import.meta.url));
const mode = process.argv[2] ?? 'all';
const bindgen = process.env.WASM_BINDGEN ?? 'wasm-bindgen';
const nightly = process.env.RUST_NIGHTLY ?? 'nightly-2026-03-04';
function run(command, args, env = {}) {
  const result = spawnSync(command, args, { cwd: root, stdio: 'inherit', env: { ...process.env, ...env } });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} exited ${result.status}`);
}
async function wasm(threaded) {
  const name = threaded ? 'threads' : 'single';
  const target = path.join(root, 'target', `wasm-${name}`);
  const output = path.join(root, `pkg-${name}`);
  const args = [
    ...(threaded ? [`+${nightly}`] : []), 'build', '--release', '--lib', '--target', 'wasm32-unknown-unknown',
    '--no-default-features', '--features', threaded ? 'threads' : 'wasm',
    ...(threaded ? ['-Z', 'build-std=std,panic_abort'] : []),
  ];
  run('cargo', args, {
    CARGO_TARGET_DIR: target,
    RUSTFLAGS: [process.env.RUSTFLAGS ?? '', threaded ? '-C target-feature=+atomics,+bulk-memory,+mutable-globals -C link-arg=--shared-memory -C link-arg=--import-memory -C link-arg=--max-memory=4294967296 -C link-arg=--export=__heap_base -C link-arg=--export=__wasm_init_tls -C link-arg=--export=__tls_size -C link-arg=--export=__tls_align -C link-arg=--export=__tls_base' : ''].join(' ').trim(),
  });
  run(bindgen, ['--target', 'web', '--out-dir', output, '--out-name', 'passport_groth16', path.join(target, 'wasm32-unknown-unknown/release/passport_groth16.wasm')]);
  await writeFile(path.join(output, 'package.json'), '{"type":"module"}\n');
  if (threaded) {
    await copyFile(path.join(root, 'worker-runtime.mjs'), path.join(output, 'worker-runtime.mjs'));
    // Only replace the generated worker transport, never Rust/crypto source.
    const snippets = path.join(output, 'snippets');
    let found = false;
    for (const directory of await readdir(snippets)) {
      if (!directory.startsWith('wasm-bindgen-rayon-')) continue;
      await rm(path.join(snippets, directory, 'workerHelpers.js'), { force: true });
      await writeFile(path.join(snippets, directory, 'src/workerHelpers.js'), "export { startWorkers } from '../../../worker-runtime.mjs';\n");
      found = true;
    }
    if (!found) throw new Error('Missing wasm-bindgen-rayon generated worker snippet');
  }
  console.log(JSON.stringify({ backend: 'arkworks-groth16-bn254', mode: name, module: path.join(output, 'passport_groth16.js'), wasm: path.join(output, 'passport_groth16_bg.wasm') }));
}

if (!['vendor', 'native', 'wasm', 'threads', 'all'].includes(mode)) throw new Error('Usage: node build.mjs [vendor|native|wasm|threads|all]');
await ensureArkEc();
if (mode === 'native' || mode === 'all') run('cargo', ['build', '--release', '--bin', 'passport-groth16', '--features', 'parallel']);
if (mode === 'wasm' || mode === 'all') await wasm(false);
if (mode === 'threads' || mode === 'all') await wasm(true);
