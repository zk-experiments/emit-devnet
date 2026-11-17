import { callRust, freeRust } from './wasm-lifecycle.mjs';
const contexts = new Set();
const decoder = new TextDecoder();
let instance = 0;

function bytes(assets, name) {
  const value = assets[name];
  if (!(value instanceof Uint8Array)) throw new TypeError(`Groth16 asset ${name} must be Uint8Array`);
  return value;
}

async function openRuntime(assets, threads) {
  if (!Number.isInteger(threads) || threads < 1) throw new Error('Groth16 threads must be a positive integer');
  const threaded = threads > 1;
  if (threaded && typeof SharedArrayBuffer === 'undefined') throw new Error('Groth16 threads require SharedArrayBuffer and browser cross-origin isolation');
  const mode = threaded ? 'threads' : 'single';
  const url = new URL(`./groth16/pkg-${mode}/passport_groth16.js`, import.meta.url);
  // Fresh module state permits dispose + prepare again without a stale Rayon pool.
  url.searchParams.set('instance', String(++instance));
  const api = await import(url.href);
  const wasm = await api.default({ module_or_path: bytes(assets, 'wasm') });
  const runtime = threaded ? await import(new URL('./groth16/pkg-threads/worker-runtime.mjs', import.meta.url)) : null;
  try {
    if (threaded) await api.initThreadPool(threads);
    if (api.threadCount() !== threads) throw new Error(`Groth16 Rayon pool has ${api.threadCount()} threads, expected ${threads}`);
  } catch (error) {
    if (runtime) await runtime.stopWorkers(wasm.memory);
    throw error;
  }
  const context = { api, wasm, runtime, poisoned: null, resources: new Set() };
  contexts.add(context);
  return context;
}

function wrap(session, context, prove) {
  const { api, wasm, runtime } = context;
  context.resources.add(session);
  const stats = {
    ...JSON.parse(callRust(context, () => session.stats)), threads: api.threadCount(), backend: 'arkworks-groth16-bn254',
    proof_encoding: 'arkworks-canonical-point-compressed', compression: null,
  };
  let disposed = false;
  function live() {
    if (context.poisoned) throw context.poisoned;
    if (disposed) throw new Error('Groth16 session disposed');
  }
  return {
    stats,
    ...(prove ? { async prove() { live(); return callRust(context, prove); } } : {}),
    async verify(proof) {
      live();
      try { return callRust(context, () => session.verify(proof)); }
      catch (error) { if (context.poisoned) throw error; return false; }
    },
    // Normal verify always uses the immutable fixture statement.
    async verifyPublic(proof, publicValues) {
      live();
      try { return callRust(context, () => session.verifyPublic(proof, JSON.stringify(publicValues))); }
      catch (error) { if (context.poisoned) throw error; return false; }
    },
    proofBytes(proof) {
      if (!(proof instanceof Uint8Array)) throw new TypeError('Expected canonical Groth16 proof bytes');
      return proof;
    },
    uncompressedProofBytes(proof) { live(); return callRust(context, () => api.uncompressProof(proof)); },
    get memoryBytes() { return wasm.memory.buffer.byteLength; },
    async dispose() {
      if (disposed) return;
      disposed = true;
      try { freeRust(context, session); }
      finally {
        session = null;
        if (runtime) await runtime.stopWorkers(wasm.memory);
        if (!context.poisoned) contexts.delete(context);
      }
    },
  };
}

/** Assets: {manifest, pk, vk, r1cs, wasm}, all Uint8Array.
 * JS bindings/snippets live under groth16/pkg-{single,threads}.
 */
export async function prepare({ fixture, assets, threads = 1 }) {
  const manifestText = decoder.decode(bytes(assets, 'manifest'));
  const manifest = JSON.parse(manifestText);
  if (manifest.stats.wasm32_lower_bound_bytes >= 4_294_901_760) {
    throw new Error(`wasm32 blocker: mandatory Groth16 queries, QAP vectors and assignment require at least ${manifest.stats.wasm32_lower_bound_bytes} bytes, before ACVM/FFT/MSM scratch`);
  }
  const pk = bytes(assets, 'pk');
  const vk = bytes(assets, 'vk');
  const plan = bytes(assets, 'r1cs');
  if (pk.byteLength !== manifest.stats.prover_key_bytes || vk.byteLength !== manifest.stats.verifier_key_bytes || plan.byteLength !== manifest.stats.matrix_plan_bytes) throw new Error('Groth16 artifact size mismatch');
  const context = await openRuntime(assets, threads);
  try {
    const text = typeof fixture === 'string' ? fixture : JSON.stringify(fixture);
    const session = callRust(context, () => context.api.loadSession(text, manifestText, (offset, length) => pk.subarray(offset, offset + length), pk.byteLength, vk));
    return wrap(session, context, () => session.prove((offset, length) => plan.subarray(offset, offset + length), plan.byteLength));
  } catch (error) {
    if (context.runtime) await context.runtime.stopWorkers(context.wasm.memory);
    throw error;
  }
}

/** Verification only: assets {manifest, vk, wasm}; never loads a PK or R1CS plan. */
export async function prepareVerifier({ fixture, assets, threads = 1 }) {
  const context = await openRuntime(assets, threads);
  try {
    const text = typeof fixture === 'string' ? fixture : JSON.stringify(fixture);
    const session = callRust(context, () => context.api.loadVerifier(text, decoder.decode(bytes(assets, 'manifest')), bytes(assets, 'vk')));
    return wrap(session, context);
  } catch (error) {
    if (context.runtime) await context.runtime.stopWorkers(context.wasm.memory);
    throw error;
  }
}
