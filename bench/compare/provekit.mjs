import { callRust, freeRust } from './wasm-lifecycle.mjs';

export const backend = 'ProveKit BN254 WHIR/R1CS (SHA-256, hiding commitments)';
export const proofEncoding = 'Postcard binary WHIR transcript (native transport)';
export const compression = null;
export const artifactFiles = { manifest: 'manifest.json', r1cs: 'r1cs.bin' };
export const runtimeFiles = threads => ({
  runtime: new URL(`./provekit/pkg/${threads === 1 ? 'single' : 'threads'}/passport_provekit.js`, import.meta.url),
  wasm: new URL(`./provekit/pkg/${threads === 1 ? 'single' : 'threads'}/passport_provekit_bg.wasm`, import.meta.url),
});
const initialized = new Map();
const decoder = new TextDecoder();

async function initialize(assets, threads) {
  if (!Number.isSafeInteger(threads) || threads < 1) throw new Error('Expected a positive ProveKit thread count');
  for (const key of ['manifest', 'r1cs', 'wasm']) {
    if (!(assets[key] instanceof Uint8Array)) throw new Error(`Missing ProveKit ${key} bytes`);
  }
  if (threads > 1 && (typeof SharedArrayBuffer === 'undefined'
      || (typeof process === 'undefined' && !globalThis.crossOriginIsolated))) {
    throw new Error('Threaded ProveKit requires shared WASM memory and cross-origin isolation');
  }
  const url = runtimeFiles(threads).runtime.href;
  if (!initialized.has(url)) {
    initialized.set(url, (async () => {
      const runtime = await import(url);
      const wasm = await runtime.default({ module_or_path: assets.wasm });
      const context = { runtime, wasm, threads, poisoned: null, resources: new Set() };
      try {
        if (threads > 1) await runtime.initThreadPool(threads);
        else runtime.initSingleThread();
        if (runtime.threadCount() !== threads) throw new Error('ProveKit actual Rayon thread count mismatch');
      } catch (error) {
        callRust(context, () => { throw error; });
      }
      return context;
    })());
  }
  const context = await initialized.get(url);
  if (context.poisoned) throw context.poisoned;
  if (context.threads !== threads) throw new Error('Run each thread count in a separate Worker');
  return context;
}

function wrap(context, session, canProve) {
  // Keep every live Rust handle rooted. After a trap these roots intentionally
  // survive dispose(), preventing FinalizationRegistry from freeing a borrowed
  // value before the caller terminates its dedicated Worker/process.
  context.resources.add(session);
  const stats = JSON.parse(callRust(context, () => session.stats()));
  let disposed = false;
  function live() {
    if (context.poisoned) throw context.poisoned;
    if (disposed) throw new Error('Disposed ProveKit session');
  }
  const result = {
    stats,
    threads: context.threads,
    get memoryBytes() { return context.wasm.memory.buffer.byteLength; },
    get poisoned() { return Boolean(context.poisoned); },
    async verify(proof) {
      live();
      if (!(proof instanceof Uint8Array)) return false;
      // Rust returns false for invalid proofs. JS exceptions, especially fatal
      // RuntimeErrors, must not be reclassified as ordinary proof rejection.
      return callRust(context, () => session.verify(proof));
    },
    proofBytes(proof) {
      if (!(proof instanceof Uint8Array)) throw new Error('Expected postcard-encoded WHIR proof');
      return proof;
    },
    dispose() {
      if (disposed) return;
      disposed = true;
      freeRust(context, session);
      session = null;
    },
  };
  if (canProve) result.prove = async () => {
    live();
    return callRust(context, () => session.prove());
  };
  return result;
}

export async function prepare({ fixture, assets, threads = 1 }) {
  if (threads !== 1 && threads !== 6) throw new Error('ProveKit proving supports 1 or 6 threads');
  const context = await initialize(assets, threads);
  const text = typeof fixture === 'string' ? fixture : JSON.stringify(fixture);
  const session = callRust(context, () => new context.runtime.Session(text, decoder.decode(assets.manifest), assets.r1cs));
  return wrap(context, session, true);
}

// Same R1CS/scheme verification assets; no ACIR decode or witness generation.
export async function prepareVerifier({ fixture, assets, threads = 1 }) {
  const context = await initialize(assets, threads);
  const text = typeof fixture === 'string' ? fixture : JSON.stringify(fixture);
  const verifier = callRust(context, () => new context.runtime.Verifier(text, decoder.decode(assets.manifest), assets.r1cs));
  return wrap(context, verifier, false);
}
