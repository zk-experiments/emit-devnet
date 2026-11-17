import { spawnSync } from 'node:child_process';
import { readFile, writeFile, readdir, copyFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('.', import.meta.url));
const toolchain = 'nightly-2026-03-04';
const bindings = '0.2.114';
function run(command, args, extra = {}) {
  const result = spawnSync(command, args, { cwd: root, stdio: 'inherit', ...extra });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} exited ${result.status}`);
}
const mode = process.argv[2];
if (!['native', 'wasm', 'all', 'prepare'].includes(mode)) {
  console.log(`Build requirements: rustup toolchain install ${toolchain} --component rust-src --target wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version ${bindings} --locked
node bench/compare/provekit/build.mjs native|wasm|all
node bench/compare/provekit/build.mjs prepare bench/fixtures/PIPELINE/comparison.json OUTPUT [1|6]
Native: bench/compare/provekit/target/native/release/passport-provekit prove|verify|verify-once FIXTURE OUTPUT PROOF [THREADS] [REPEATS]
verify defaults to all available host cores, warms once, then emits20 verify_ms samples and verify_median_ms (optional REPEATS overrides20), with keys/proof loaded once. verify-once performs one correctness check.
WASM output: bench/compare/provekit/pkg/{single,threads}/{passport_provekit.js,passport_provekit_bg.wasm}
Native prepare writes OUTPUT/{manifest.json,r1cs.bin}. Adapter assets: manifest,r1cs,wasm; runtimeFiles(threads) supplies runtime and WASM URLs.
WASM prepareVerifier({fixture,assets,threads}) accepts any positive thread count and retains only the decoded R1CS verification key, expected public vector, and scheme.
Run each thread count in a dedicated Worker. Browser threaded mode needs COOP:same-origin and COEP:require-corp.`);
} else if (mode === 'prepare') {
  const [fixture, output, threads = '1'] = process.argv.slice(3);
  if (!fixture || !output) throw new Error('prepare requires FIXTURE OUTPUT');
  run(join(root, 'target/native/release/passport-provekit'), ['prepare', fixture, output, threads], { cwd: process.cwd() });
} else {
  try { await readFile(join(root, 'Cargo.lock')); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    run('cargo', [`+${toolchain}`, 'generate-lockfile']);
  }
  if (mode === 'native' || mode === 'all') {
    run('cargo', [`+${toolchain}`, 'build', '--locked', '--release', '--target-dir', 'target/native']);
  }
  if (mode === 'wasm' || mode === 'all') {
    const version = spawnSync('wasm-bindgen', ['--version'], { encoding: 'utf8' });
    if (version.stdout?.trim() !== `wasm-bindgen ${bindings}`) throw new Error(`Install wasm-bindgen-cli ${bindings}`);
    for (const threaded of [false, true]) {
      const name = threaded ? 'threads' : 'single';
      const target = join(root, `target/${name}`);
      const args = [`+${toolchain}`, 'build', '--locked', '--release', '--lib', '--target', 'wasm32-unknown-unknown', '--target-dir', target];
      if (threaded) args.push('--features', 'threads', '-Z', 'build-std=std,panic_abort');
      const flags = threaded
        ? '-C target-feature=+atomics,+bulk-memory,+mutable-globals,+simd128,+relaxed-simd,-reference-types -C link-arg=--shared-memory -C link-arg=--import-memory -C link-arg=--max-memory=4294967296 -C link-arg=--export=__wasm_init_tls -C link-arg=--export=__tls_size -C link-arg=--export=__tls_align -C link-arg=--export=__tls_base'
        : '-C target-feature=+bulk-memory,+mutable-globals,+simd128,+relaxed-simd,-atomics';
      const env = { ...process.env, RUSTFLAGS: flags };
      delete env.CARGO_ENCODED_RUSTFLAGS;
      run('cargo', args, { env });
      const output = join(root, `pkg/${name}`);
      await mkdir(output, { recursive: true });
      run('wasm-bindgen', ['--target', 'web', '--out-dir', output,
        join(target, 'wasm32-unknown-unknown/release/passport_provekit.wasm')]);
      if (threaded) {
        const snippets = join(output, 'snippets');
        let replaced = 0;
        for (const entry of await readdir(snippets)) {
          if (!entry.startsWith('wasm-bindgen-rayon-')) continue;
          await copyFile(join(root, 'worker-helpers.mjs'), join(snippets, entry, 'src/workerHelpers.no-bundler.js'));
          replaced++;
        }
        if (replaced !== 1) throw new Error(`Expected one pinned Rayon helper, found ${replaced}`);
      }
      await writeFile(join(output, 'package.json'), '{"type":"module"}\n');
    }
  }
}
