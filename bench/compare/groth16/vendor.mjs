#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { access, mkdir, mkdtemp, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('.', import.meta.url));
const PACKAGE = 'ark-ec-0.6.0';
const ARCHIVE_URL = `https://static.crates.io/crates/ark-ec/${PACKAGE}.crate`;
const SHA256 = '8352a2b2aedf6ba2cc38f7520fc51191d518dde96175c729af19f2d059f191c4';
const MODULE = 'src/scalar_mul/variable_base/mod.rs';
const ORIGINAL = `            #[cfg(feature = "parallel")]
            let result = rayon::ThreadPoolBuilder::new()
                .num_threads(THREADS_PER_CHUNK.min(rayon::current_num_threads()))
                .build()
                .unwrap()
                .install(|| msm_bigint_wnaf_parallel::<V>(bases, scalars));

            #[cfg(not(feature = "parallel"))]
            let result = msm_bigint_wnaf_parallel::<V>(bases, scalars);`;
const PATCHED = `            #[cfg(all(feature = "parallel", not(target_arch = "wasm32")))]
            let result = rayon::ThreadPoolBuilder::new()
                .num_threads(THREADS_PER_CHUNK.min(rayon::current_num_threads()))
                .build()
                .unwrap()
                .install(|| msm_bigint_wnaf_parallel::<V>(bases, scalars));

            // WASM workers already run in wasm-bindgen-rayon's global pool.
            // Keep the same WNAF closure/math without unsupported native subpools.
            #[cfg(any(not(feature = "parallel"), target_arch = "wasm32"))]
            let result = msm_bigint_wnaf_parallel::<V>(bases, scalars);`;

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
async function exists(file) {
  try { await access(file); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; }
}
async function tree(directory, prefix = '') {
  const files = [];
  for (const entry of await readdir(path.join(directory, prefix), { withFileTypes: true })) {
    const relative = path.join(prefix, entry.name);
    if (entry.isDirectory()) files.push(...await tree(directory, relative));
    else if (entry.isFile()) files.push([relative, hash(await readFile(path.join(directory, relative)))]);
    else throw new Error(`Unexpected vendored entry: ${relative}`);
  }
  return files.sort(([a], [b]) => a.localeCompare(b));
}
async function archive(vendor) {
  const downloaded = path.join(vendor, `${PACKAGE}.crate`);
  if (await exists(downloaded)) return downloaded;
  const cache = path.join(process.env.CARGO_HOME ?? path.join(homedir(), '.cargo'), 'registry/cache');
  let registries = [];
  try { registries = await readdir(cache); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  for (const registry of registries) {
    const candidate = path.join(cache, registry, `${PACKAGE}.crate`);
    if (await exists(candidate)) return candidate;
  }
  const response = await fetch(ARCHIVE_URL);
  if (!response.ok) throw new Error(`Cannot download pinned ${PACKAGE}: HTTP ${response.status}`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (hash(bytes) !== SHA256) throw new Error(`Pinned ${PACKAGE} archive checksum mismatch`);
  await writeFile(downloaded, bytes, { flag: 'wx' });
  return downloaded;
}

/** Generate only a scheduler overlay; reject upstream or local source mismatch. */
export async function ensureArkEc() {
  const vendor = path.join(ROOT, 'vendor');
  const destination = path.join(vendor, PACKAGE);
  await mkdir(vendor, { recursive: true });
  const source = await archive(vendor);
  if (hash(await readFile(source)) !== SHA256) throw new Error(`Pinned ${PACKAGE} archive checksum mismatch`);
  const staging = await mkdtemp(path.join(vendor, '.ark-ec-stage-'));
  try {
    execFileSync('tar', ['-xzf', source, '-C', staging]);
    const directory = path.join(staging, PACKAGE);
    const module = path.join(directory, MODULE);
    const original = await readFile(module, 'utf8');
    if (original.split(ORIGINAL).length !== 2) throw new Error(`Pinned ${PACKAGE} scheduler source mismatch`);
    const patched = original.replace(ORIGINAL, PATCHED);
    await writeFile(module, patched);
    // The archive's complete upstream LICENSE-MIT and LICENSE-APACHE stay intact.
    const provenance = {
      package: PACKAGE, archive_url: ARCHIVE_URL, archive_sha256: SHA256,
      source_module: MODULE, original_module_sha256: hash(original), patched_module_sha256: hash(patched),
      change: 'wasm32 scheduler only: execute the unchanged WNAF closure on the existing global Rayon pool; native branch unchanged',
      licenses: ['LICENSE-MIT', 'LICENSE-APACHE'],
    };
    await writeFile(path.join(directory, 'SCHEDULER-PATCH.json'), JSON.stringify(provenance, null, 2) + '\n');
    if (await exists(path.join(destination, 'Cargo.toml'))) {
      if (JSON.stringify(await tree(directory)) !== JSON.stringify(await tree(destination))) {
        throw new Error(`Local ${PACKAGE} overlay differs from the pinned scheduler-only source; refusing to overwrite`);
      }
    } else {
      await rename(directory, destination);
    }
    return provenance;
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(await ensureArkEc()));
}
