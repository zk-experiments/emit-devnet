#!/usr/bin/env node
// WASM benchmark of the Chonk pipelines: witness (acvm_js) + prove/verify (bb.js WASM),
// replaying the folds dumped by ../fixtures.sh. One fresh process per sample under
// `/usr/bin/time -l` for peak RSS (macOS), like outbe-circuits' groth16-tribute.
//
//   node bench.mjs run [--samples 5] [--threads 1,6] [--pipelines a,b]
//   node bench.mjs __sample <pipeline> <threads>   (one sample, JSON on stdout)
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { gzipSync, gunzipSync } from 'node:zlib';
import { performance } from 'node:perf_hooks';
import { Barretenberg, BackendType, flattenChonkProofFields } from '@aztec-foundation/bb.js';
import { executeCircuit, compressWitnessStack } from '@noir-lang/acvm_js';

const here = path.dirname(new URL(import.meta.url).pathname);
const FIXTURES = path.join(here, '..', 'fixtures');
const BB_JS = '7.0.0-nightly.20261110';
const ACVM_JS = '1.0.0-rc.5';
const KINDS = ['app', 'kernel', 'hiding'];

const load = p => ({
  steps: JSON.parse(fs.readFileSync(path.join(FIXTURES, p, 'fold.json'))),
  publics: JSON.parse(fs.readFileSync(path.join(FIXTURES, p, 'public.json'))),
  nativeProof: fs.readFileSync(path.join(FIXTURES, p, 'proof.bin')),
});
const hex32 = f => '0x' + Buffer.from(f).toString('hex');
const fields = buf => Array.from({ length: buf.length / 32 }, (_, i) => buf.subarray(i * 32, i * 32 + 32));

async function sample(pipeline, threads) {
  const { steps, publics, nativeProof } = load(pipeline);
  const stages = [];
  const timed = async (stage, f, step) => {
    const t = performance.now();
    const r = await f();
    stages.push({ stage, step, ms: performance.now() - t });
    return r;
  };
  const api = await timed('bb_init', async () => {
    const api = await Barretenberg.new({ backend: BackendType.Wasm, threads });
    await api.initSRSChonk();
    return api;
  });

  // Witness: what the device computes; inputs (incl. the kernels') are the dumped ones.
  const witnesses = [];
  for (const s of steps) {
    const bytecode = Buffer.from(s.bytecode, 'base64');
    const program = gzipSync(bytecode);
    const initial = new Map(s.inputs.map((v, i) => [i, v]));
    const solved = await timed('witness', () => executeCircuit(program, initial, async () => []), s.name);
    witnesses.push(
      await timed('witness_encode', () => gunzipSync(compressWitnessStack([{ index: 0, witness: solved }])), s.name),
    );
    s.bytecodeRaw = bytecode;
  }

  const t0 = performance.now();
  await timed('chonk_start', () => api.chonkStart({ kinds: Uint8Array.from(steps.map(s => s.kind)) }));
  for (const [i, s] of steps.entries()) {
    await timed('chonk_load', () =>
      api.chonkLoad({
        circuit: { name: s.name, bytecode: s.bytecodeRaw, verificationKey: Buffer.from(s.vk, 'hex') },
        kind: s.kind,
      }), s.name);
    await timed('chonk_accumulate', () => api.chonkAccumulate({ witness: witnesses[i] }), s.name);
  }
  const { proof } = await timed('chonk_prove', () => api.chonkProve({}));
  stages.push({ stage: 'prove', ms: performance.now() - t0 });

  const hidingVk = Buffer.from(steps.at(-1).vk, 'hex');
  const { valid } = await timed('verify', () => api.chonkVerify({ proof, vk: hidingVk }));
  const flat = flattenChonkProofFields(proof);
  const { compressedProof } = await api.chonkCompressProof({ proof });

  // Sanity: same public outputs as the native fold, the native proof verifies here, a
  // tampered one doesn't.
  const pubOk = publics.every((p, i) => BigInt(hex32(flat[i])) === BigInt(p));
  const native = fields(nativeProof);
  const nativeOk = (await api.chonkVerifyFromFields({ proof: native, vk: hidingVk })).valid;
  const bad = Buffer.from(nativeProof);
  bad[bad.length - 1] ^= 1;
  let tamperRejected = true;
  try {
    tamperRejected = !(await api.chonkVerifyFromFields({ proof: fields(bad), vk: hidingVk })).valid;
  } catch {}
  await api.destroy();
  if (!valid || !pubOk || !nativeOk || !tamperRejected)
    throw new Error(`${pipeline}: checks failed ${JSON.stringify({ valid, pubOk, nativeOk, tamperRejected })}`);

  return {
    pipeline, threads, stages,
    sizes: { proof: flat.length * 32, proofCompressed: compressedProof.length, vk: hidingVk.length },
  };
}

// Per-circuit structure (not timed): gates and ACIR opcodes as Chonk builds them.
async function stats(pipeline) {
  const { steps } = load(pipeline);
  const api = await Barretenberg.new({ backend: BackendType.Wasm, threads: os.availableParallelism() });
  const out = [];
  for (const s of steps) {
    const r = await api.chonkStats({
      circuit: { name: s.name, bytecode: Buffer.from(s.bytecode, 'base64') },
      includeGatesPerOpcode: false,
    });
    out.push({ name: s.name, kind: KINDS[s.kind], gates: r.circuitSize, opcodes: r.acirOpcodes });
  }
  await api.destroy();
  return out;
}

function child(args) {
  const r = spawnSync('/usr/bin/time', ['-l', process.execPath, new URL(import.meta.url).pathname, ...args], {
    encoding: 'utf8',
    maxBuffer: 1 << 28,
  });
  if (r.status !== 0) throw new Error(`${args.join(' ')} failed:\n${r.stderr.slice(-4000)}`);
  const num = re => +(re.exec(r.stderr)?.[1] ?? NaN);
  return {
    ...JSON.parse(r.stdout.trim().split('\n').at(-1) || '{}'),
    peakRss: num(/(\d+)\s+maximum resident set size/),
    peakFootprint: num(/(\d+)\s+peak memory footprint/),
  };
}

const median = xs => [...xs].sort((a, b) => a - b)[Math.floor((xs.length - 1) / 2)];
const fmt = (xs, d = 0) => {
  const m = median(xs).toFixed(d);
  return xs.length > 1 ? `${m} (${Math.min(...xs).toFixed(d)}–${Math.max(...xs).toFixed(d)})` : m;
};
const MiB = 1 << 20;
const pow2 = n => 2 ** Math.ceil(Math.log2(n));

function sh(cmd) {
  return spawnSync('sh', ['-c', cmd], { encoding: 'utf8' }).stdout.trim();
}

async function run(opts) {
  const pipelines = opts.pipelines ?? fs.readdirSync(FIXTURES).filter(d => fs.existsSync(path.join(FIXTURES, d, 'fold.json')));
  const threads = (opts.threads ?? '1,6').split(',').map(Number);
  const samples = +(opts.samples ?? 5);
  const out = path.join(here, '..', 'results', new Date().toISOString().slice(0, 10));
  fs.mkdirSync(out, { recursive: true });

  // Node's own share of the memory numbers.
  const baseline = child(['__baseline']);
  const circuits = {};
  for (const p of pipelines) circuits[p] = child(['__stats', p]).circuits;

  const rows = [];
  for (const p of pipelines)
    for (const t of threads)
      for (let i = 1; i <= samples; i++) {
        process.stderr.write(`${p} threads=${t} sample ${i}/${samples}\n`);
        rows.push({ ...child(['__sample', p, String(t)]), sample: i });
      }

  const stage = (r, name) => r.stages.filter(s => s.stage === name).reduce((a, s) => a + s.ms, 0);
  const csv = ['pipeline,threads,sample,stage,step,ms'];
  for (const r of rows) for (const s of r.stages) csv.push([r.pipeline, r.threads, r.sample, s.stage, s.step ?? '', s.ms.toFixed(3)].join(','));
  csv.push('', 'pipeline,threads,sample,peak_rss_bytes,peak_footprint_bytes,proof_bytes,proof_compressed_bytes,vk_bytes');
  for (const r of rows) csv.push([r.pipeline, r.threads, r.sample, r.peakRss, r.peakFootprint, r.sizes.proof, r.sizes.proofCompressed, r.sizes.vk].join(','));
  fs.writeFileSync(path.join(out, 'timings.csv'), csv.join('\n') + '\n');

  const meta = {
    date: new Date().toISOString(),
    cpu: sh('sysctl -n machdep.cpu.brand_string'),
    logicalCores: os.availableParallelism(),
    memGiB: +(os.totalmem() / 2 ** 30).toFixed(1),
    os: `${os.type()} ${os.release()}`,
    node: process.version, v8: process.versions.v8,
    bbJs: BB_JS, acvmJs: ACVM_JS,
    commit: sh('git -C ' + here + ' rev-parse --short HEAD'),
    samples, threads,
    nodeBaseline: { peakRss: baseline.peakRss, peakFootprint: baseline.peakFootprint },
  };
  fs.writeFileSync(path.join(out, 'metadata.json'), JSON.stringify(meta, null, 2) + '\n');

  const L = [];
  L.push('# Circuit benchmarks (WASM)', '');
  L.push(`Machine: ${meta.cpu}, ${meta.logicalCores} logical cores, ${meta.memGiB} GiB · ${meta.os} · Node ${meta.node} (V8 ${meta.v8})`);
  L.push(`Stack: \`@aztec-foundation/bb.js@${BB_JS}\` (WASM backend) + \`@noir-lang/acvm_js@${ACVM_JS}\` · commit \`${meta.commit}\` · ${samples} samples per row, each a fresh process`, '');
  L.push('A proof is a Chonk fold of a whole pipeline (apps + noir-zk kernels + hiding kernel), so numbers are per pipeline.');
  L.push('Values are median (min–max). Threads: 1 = no SharedArrayBuffer (plain WKWebView), 6 = iPhone 17 core count.');
  L.push('This is V8 on a Mac: expect a phone (JavaScriptCore, slower cores, iOS memory limits, wasm32 4 GiB cap) to be slower — treat these as a lower bound.', '');

  L.push('## Pipelines', '');
  L.push('| Pipeline | Threads | Circuits | Σ gates | Witness ms | Prove ms | **Witness + prove ms** | Peak footprint MiB | Peak RSS MiB | Verify ms | Proof B (compressed) | VK B |');
  L.push('|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|');
  for (const p of pipelines)
    for (const t of threads) {
      const rs = rows.filter(r => r.pipeline === p && r.threads === t);
      const c = circuits[p];
      const w = rs.map(r => stage(r, 'witness') + stage(r, 'witness_encode'));
      const pr = rs.map(r => stage(r, 'prove'));
      L.push(`| ${p} | ${t} | ${c.length} | ${c.reduce((a, x) => a + x.gates, 0).toLocaleString('en')} | ${fmt(w)} | ${fmt(pr)} | **${fmt(w.map((x, i) => x + pr[i]))}** | ${fmt(rs.map(r => r.peakFootprint / MiB))} | ${fmt(rs.map(r => r.peakRss / MiB))} | ${fmt(rs.map(r => stage(r, 'verify')), 1)} | ${rs[0].sizes.proof} (${rs[0].sizes.proofCompressed}) | ${rs[0].sizes.vk} |`);
    }

  L.push('', '## Circuits', '');
  L.push(`Witness ms is the median at ${threads[0]} thread(s) (ACVM is single-threaded). Dyadic = the power-of-two size bb proves at.`, '');
  L.push('| Pipeline | # | Circuit | Role | ACIR opcodes | Gates | Dyadic | Witness ms |');
  L.push('|---|---:|---|---|---:|---:|---:|---:|');
  for (const p of pipelines) {
    const rs = rows.filter(r => r.pipeline === p && r.threads === threads[0]);
    circuits[p].forEach((c, i) => {
      const w = rs.map(r => r.stages.filter(s => s.stage === 'witness')[i].ms);
      L.push(`| ${p} | ${i} | ${c.name} | ${c.kind} | ${c.opcodes.toLocaleString('en')} | ${c.gates.toLocaleString('en')} | ${pow2(c.gates).toLocaleString('en')} | ${fmt(w, 1)} |`);
    });
  }

  L.push('', '## Prove breakdown', '');
  L.push('| Pipeline | Threads | bb init (WASM + SRS) ms | Load ms | Accumulate ms | Final prove ms |');
  L.push('|---|---:|---:|---:|---:|---:|');
  for (const p of pipelines)
    for (const t of threads) {
      const rs = rows.filter(r => r.pipeline === p && r.threads === t);
      L.push(`| ${p} | ${t} | ${['bb_init', 'chonk_load', 'chonk_accumulate', 'chonk_prove'].map(s => fmt(rs.map(r => stage(r, s)))).join(' | ')} |`);
    }

  L.push('', '## Method', '');
  L.push('- Inputs: `bench/fixtures.sh` folds each pipeline natively once and dumps every circuit, its inputs (kernels\' too) and the proof; the WASM run replays them.');
  L.push('- Witness = `acvm_js.executeCircuit` per circuit + witness-stack encoding. Prove = bb `chonkStart` → `chonkLoad`/`chonkAccumulate` per circuit → `chonkProve`. Verify = `chonkVerify` against the hiding kernel\'s VK. bb init (WASM instantiate + SRS) is reported separately, not in prove.');
  L.push(`- Memory = whole process from \`/usr/bin/time -l\`: peak footprint (phys_footprint, the figure iOS's jetsam limit applies to) and peak RSS. Both include Node itself: an empty \`node\` peaks at ${(baseline.peakFootprint / MiB).toFixed(0)} MiB footprint / ${(baseline.peakRss / MiB).toFixed(0)} MiB RSS here.`);
  L.push('- Checks per sample: the proof verifies, its public outputs equal the native fold\'s, the native proof verifies in WASM, a tampered one is rejected.');
  L.push('- Proof B = proof as 32-byte fields (what the chain verifies); compressed = bb\'s point-compressed form.');
  fs.writeFileSync(path.join(out, 'report.md'), L.join('\n') + '\n');
  console.log(path.join(out, 'report.md'));
}

const [cmd, ...rest] = process.argv.slice(2);
if (cmd === '__sample') console.log(JSON.stringify(await sample(rest[0], +rest[1])));
else if (cmd === '__baseline') console.log('{}');
else if (cmd === '__stats') console.log(JSON.stringify({ circuits: await stats(rest[0]) }));
else if (cmd === 'run') {
  const opts = {};
  for (let i = 0; i < rest.length; i += 2) opts[rest[i].replace(/^--/, '')] = rest[i + 1];
  if (opts.pipelines) opts.pipelines = opts.pipelines.split(',');
  await run(opts);
} else {
  console.error('usage: node bench.mjs run [--samples N] [--threads 1,6] [--pipelines a,b]');
  process.exit(1);
}
process.exit(0);
