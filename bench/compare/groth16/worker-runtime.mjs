// wasm-bindgen-rayon 1.3 startWorkers protocol; browser and Node use real workers.
const node = typeof process !== 'undefined' && Boolean(process.versions?.node);
const nodeWorkers = node ? await import('node:worker_threads') : null;
const workerScope = node ? !nodeWorkers.isMainThread : typeof WorkerGlobalScope !== 'undefined' && globalThis instanceof WorkerGlobalScope;
const port = node ? nodeWorkers.parentPort : globalThis;
const pools = new Map();

function onMessage(target, listener) {
  if (node) {
    const wrapped = data => listener({ data });
    target.on('message', wrapped);
    return () => target.off('message', wrapped);
  }
  target.addEventListener('message', listener);
  return () => target.removeEventListener('message', listener);
}

if (workerScope) {
  const remove = onMessage(port, async ({ data }) => {
    if (data?.type !== 'wasm_bindgen_worker_init') return;
    remove();
    try {
      const api = await import(new URL('./passport_groth16.js', import.meta.url));
      await api.default({ module_or_path: data.module, memory: data.memory });
      port.postMessage({ type: 'wasm_bindgen_worker_ready' });
      api.wbg_rayon_start_worker(data.receiver);
    } catch (error) {
      port.postMessage({ type: 'wasm_bindgen_worker_error', error: String(error?.stack ?? error) });
    }
  });
}

export async function startWorkers(module, memory, builder) {
  const count = builder.numThreads();
  if (!Number.isInteger(count) || count < 1) throw new Error('Invalid Rayon worker count');
  const Worker = node ? nodeWorkers.Worker : globalThis.Worker;
  const workers = [];
  pools.set(memory, workers);
  try {
    await Promise.all(Array.from({ length: count }, () => new Promise((resolve, reject) => {
      const worker = new Worker(new URL(import.meta.url), { type: 'module' });
      workers.push(worker);
      const remove = onMessage(worker, ({ data }) => {
        if (data?.type === 'wasm_bindgen_worker_ready') { remove(); resolve(); }
        if (data?.type === 'wasm_bindgen_worker_error') { remove(); reject(new Error(data.error)); }
      });
      if (node) worker.once('error', reject);
      else worker.addEventListener('error', reject, { once: true });
      worker.postMessage({ type: 'wasm_bindgen_worker_init', module, memory, receiver: builder.receiver() });
    })));
    builder.build();
  } catch (error) {
    await stopWorkers(memory);
    throw error;
  }
}

export async function stopWorkers(memory) {
  const workers = pools.get(memory) ?? [];
  pools.delete(memory);
  await Promise.all(workers.map(worker => worker.terminate()));
}
