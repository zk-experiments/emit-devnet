// Same wasm-bindgen-rayon 1.3 worker handshake and Rust pool builder; only
// worker transport differs. No bundler or Node WebWorker polyfill is required.
const node = typeof process !== 'undefined' && Boolean(process.versions?.node);
const transport = node ? await import('node:worker_threads') : null;
const workers = [];

async function start({ module, memory, receiver, mainJS }, ready) {
  const pkg = await import(mainJS);
  await pkg.default({ module_or_path: module, memory });
  ready({ type: 'wasm_bindgen_worker_ready' });
  pkg.wbg_rayon_start_worker(receiver);
}

if (node && !transport.isMainThread) {
  transport.parentPort.on('message', data => {
    if (data?.type === 'wasm_bindgen_worker_init') {
      start(data, message => transport.parentPort.postMessage(message)).catch(error => { throw error; });
    }
  });
} else if (!node && typeof self !== 'undefined') {
  self.addEventListener('message', ({ data }) => {
    if (data?.type === 'wasm_bindgen_worker_init') {
      start(data, message => self.postMessage(message)).catch(error => { throw error; });
    }
  });
}

export async function startWorkers(module, memory, builder) {
  if (builder.numThreads() < 1) throw new Error('Rayon requires a positive actual thread count');
  const init = { type: 'wasm_bindgen_worker_init', module, memory,
    receiver: builder.receiver(), mainJS: builder.mainJS() };
  await Promise.all(Array.from({ length: builder.numThreads() }, () => new Promise((resolve, reject) => {
    const worker = node
      ? new transport.Worker(new URL(import.meta.url), { type: 'module' })
      : new Worker(new URL(import.meta.url), { type: 'module' });
    workers.push(worker);
    if (node) {
      worker.once('error', reject);
      worker.on('message', data => {
        if (data?.type === 'wasm_bindgen_worker_ready') { worker.unref(); resolve(); }
      });
    } else {
      worker.addEventListener('error', reject, { once: true });
      worker.addEventListener('message', ({ data }) => {
        if (data?.type === 'wasm_bindgen_worker_ready') resolve();
      });
    }
    worker.postMessage(init);
  })));
  builder.build();
}
