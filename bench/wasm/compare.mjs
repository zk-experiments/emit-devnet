#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { readFile, writeFile, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { existsSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { renderReport } from './report-view.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const FIXTURES = path.join(ROOT, 'bench/fixtures');
const ARTIFACTS = path.join(ROOT, 'bench/artifacts');
const PIPELINES = ['identity_register_de_bp384_bp256', 'identity_register_us_rsa4096_rsa2048', 'age_verify'];
const BACKENDS = ['chonk', 'groth16', 'provekit'];
const json = async file => JSON.parse(await readFile(file, 'utf8'));
const median = values => { const a = [...values].sort((x,y)=>x-y), m = Math.floor(a.length/2); return a.length % 2 ? a[m] : (a[m-1]+a[m])/2; };
const lastJSON = text => JSON.parse(text.trim().split('\n').reverse().find(line => line.startsWith('{')) ?? '{}');
const keyDirectory = (backend, pipeline) => path.join(ARTIFACTS, backend, pipeline);

function measured(command, args, {node=true,env=process.env}={}) {
  const result = spawnSync('/usr/bin/time', ['-l', ...(node?[process.execPath,command]:[command]), ...args], { env, encoding:'utf8', maxBuffer:1<<28 });
  const stderr = result.stderr ?? '';
  const capture = expression => { const value=expression.exec(stderr)?.[1]; return value === undefined ? null : Number(value); };
  let data;
  try { data = lastJSON(result.stdout ?? ''); } catch { data = {}; }
  if (result.status !== 0 || data.error) {
    return {...data,status:'error',error:data.error ?? `${result.error?.message ?? `exit ${result.status ?? result.signal}`}\n${stderr.slice(-6000)}`,stderr:stderr.slice(-6000),
      peak_rss_bytes:capture(/(\d+)\s+maximum resident set size/), peak_footprint_bytes:capture(/(\d+)\s+peak memory footprint/)};
  }
  return {...data, status:'ok', peak_rss_bytes:capture(/(\d+)\s+maximum resident set size/), peak_footprint_bytes:capture(/(\d+)\s+peak memory footprint/)};
}

async function rustAssets(backend, pipeline, threads, verificationOnly=false) {
  const dir=keyDirectory(backend,pipeline);
  const adapter=await import(new URL(`../compare/${backend}.mjs`,import.meta.url));
  const files=backend==='groth16' ? {manifest:'manifest.json',vk:'vk.bin',...(verificationOnly?{}:{pk:'pk.bin',r1cs:'r1cs.bin'})} : {manifest:'manifest.json',r1cs:'r1cs.bin'};
  const assets={};
  for(const [role,file] of Object.entries(files)) assets[role]=await readFile(path.join(dir,file));
  const wasm=backend==='provekit' ? adapter.runtimeFiles(threads).wasm : new URL(`../compare/groth16/pkg-${threads===1?'single':'threads'}/passport_groth16_bg.wasm`,import.meta.url);
  assets.wasm=await readFile(wasm);
  return {adapter,assets,fixture:await json(path.join(FIXTURES,pipeline,'comparison.json'))};
}

async function rustSample(backend,pipeline,threads) {
  const begin=performance.now();
  const {adapter,assets,fixture}=await rustAssets(backend,pipeline,threads);
  const session=await adapter.prepare({fixture,assets,threads});
  const init=performance.now()-begin;
  try {
    const start=performance.now(), proof=await session.prove(), proved=performance.now();
    if(await session.verify(proof)!==true) throw new Error('Valid proof rejected');
    const verified=performance.now();
    const bytes=session.proofBytes(proof);
    if(!(bytes instanceof Uint8Array) || !bytes.length) throw new Error('Missing canonical proof bytes');
    const bad=bytes.slice(); bad[0]^=1;
    if(await session.verify(bad)!==false) throw new Error('Tampered proof accepted');
    const uncompressed=session.uncompressedProofBytes ? session.uncompressedProofBytes(proof) : null;
    await writeFile(path.join(keyDirectory(backend,pipeline),`proof-wasm-${threads}.bin`),bytes);
    return {initialization_ms:init,prove_ms:proved-start,verify_ms:verified-proved,verified:true,tamper_rejected:true,
      proof_bytes:uncompressed instanceof Uint8Array?uncompressed.length:bytes.length,
      compressed_proof_bytes:uncompressed instanceof Uint8Array?bytes.length:null,
      transport_proof_bytes:bytes.length,proof_encoding:session.stats?.proof_encoding??adapter.proofEncoding,
      public_bytes:fixture.expected_public.length*32,stats:session.stats,actual_threads:session.threads??threads};
  } finally {await session.dispose();}
}

async function wasmVerify(backend,pipeline,threads,count) {
  let verify,dispose,proofTransportBytes;
  if(backend==='chonk') {
    const {Barretenberg,BackendType}=await import('@aztec-foundation/bb.js');
    const steps=await json(path.join(FIXTURES,pipeline,'fold.json'));
    const proof=await readFile(path.join(FIXTURES,pipeline,'proof.bin'));
    proofTransportBytes=proof.length;
    const fields=Array.from({length:proof.length/32},(_,i)=>proof.subarray(i*32,(i+1)*32));
    const expected=await json(path.join(FIXTURES,pipeline,'public.json'));
    if(!expected.every((value,i)=>BigInt(value)===BigInt(`0x${fields[i].toString('hex')}`)))throw new Error('Full-host verification proof has the wrong public statement');
    const api=await Barretenberg.new({backend:BackendType.Wasm,threads});
    await api.initSRSChonk();
    const vk=Buffer.from(steps.at(-1).vk,'hex');
    verify=async()=> (await api.chonkVerifyFromFields({proof:fields,vk})).valid;
    dispose=()=>api.destroy();
  } else {
    const {adapter,assets,fixture}=await rustAssets(backend,pipeline,threads,true);
    const verifier=await adapter.prepareVerifier({fixture,assets,threads});
    const proof=await readFile(path.join(keyDirectory(backend,pipeline),'proof-native.bin'));
    proofTransportBytes=proof.length;
    verify=()=>verifier.verify(proof); dispose=()=>verifier.dispose();
  }
  try {
    if(await verify()!==true) throw new Error('Warm-up proof rejected');
    const samples=[];
    for(let i=0;i<count;i++) {const start=performance.now(); if(await verify()!==true)throw new Error('Proof rejected'); samples.push(performance.now()-start);}
    return {verify_samples_ms:samples,verify_median_ms:median(samples),warmups:1,threads,proof_transport_bytes:proofTransportBytes};
  } finally {await dispose();}
}

const nativeBinary = backend => path.join(ROOT, backend==='chonk'
  ? 'bench/compare/fixtures/target/release/passport-comparison-fixtures'
  : backend==='groth16' ? 'bench/compare/groth16/target/release/passport-groth16'
  : 'bench/compare/provekit/target/native/release/passport-provekit');
const nativeEnvironment = threads => ({...process.env,RAYON_NUM_THREADS:String(threads),HARDWARE_CONCURRENCY:String(threads)});

async function nativeSample(backend,pipeline,threads) {
  const temporary=backend==='chonk'?null:await mkdtemp(path.join(os.tmpdir(),'passport-native-proof-'));
  try {
    const fixture=path.join(FIXTURES,pipeline,'comparison.json'),dir=keyDirectory(backend,pipeline);
    const args=backend==='chonk' ? ['sample',pipeline,path.join(FIXTURES,pipeline),String(threads)]
      : ['prove',fixture,dir,path.join(temporary,'proof.bin'),...(backend==='provekit'?[String(threads)]:[])];
    const row=measured(nativeBinary(backend),args,{node:false,env:nativeEnvironment(threads)});
    row.requested_threads=threads;
    row.actual_threads=row.threads??null;
    if(row.status!=='ok')return row;
    if(row.verified!==true||!Number.isFinite(row.prove_ms)||row.prove_ms<0||!Number.isFinite(row.verify_ms)||row.verify_ms<0
      ||!Number.isInteger(row.proof_bytes)||row.proof_bytes<1||!Number.isInteger(row.actual_threads)||row.actual_threads<1
      ||(backend==='groth16'&&(!Number.isInteger(row.proof_uncompressed_bytes)||row.proof_uncompressed_bytes<1))) {
      return {...row,status:'error',error:'Native prover did not return verified timings, proof sizes and actual worker configuration'};
    }
    if(backend==='groth16') {
      row.compressed_proof_bytes=row.proof_bytes;
      row.proof_bytes=row.proof_uncompressed_bytes;
    } else if(backend==='provekit') row.compressed_proof_bytes=null;
    row.transport_proof_bytes=row.compressed_proof_bytes??row.proof_bytes;
    return row;
  } finally {
    if(temporary)await rm(temporary,{recursive:true,force:true});
  }
}

function nativeVerify(backend,pipeline,count) {
  const fixture=path.join(FIXTURES,pipeline,'comparison.json'), dir=keyDirectory(backend,pipeline),threads=os.availableParallelism();
  const proof=backend==='chonk'?path.join(FIXTURES,pipeline,'proof.bin'):path.join(dir,'proof-native.bin');
  const args=backend==='chonk' ? ['verify',pipeline,proof,String(count)] : backend==='groth16' ? ['verify',path.join(dir,'vk.bin'),path.join(dir,'public.json'),proof,String(count)] : ['verify',fixture,dir,proof,String(threads),String(count)];
  const data=measured(nativeBinary(backend),args,{node:false,env:nativeEnvironment(threads)});
  if(data.status!=='ok')return data;
  const samples=data.verify_samples_ms??data.verify_ms;
  if(!Array.isArray(samples)||samples.length!==count||samples.some(v=>!Number.isFinite(v)||v<0)) return {...data,status:'error',error:'Native verifier did not return the requested measured samples'};
  return {...data,status:'ok',verify_samples_ms:samples,verify_median_ms:median(samples),warmups:1,requested_threads:threads,actual_threads:data.threads??null,proof_transport_bytes:statSync(proof).size};
}

async function run(options) {
  if(process.platform!=='darwin') throw new Error('Comparable process footprint measurements require macOS /usr/bin/time -l');
  const runtime=options.runtime??'wasm';
  if(!['wasm','native'].includes(runtime))throw new Error('Runtime must be wasm or native');
  const pipelines=options.pipelines?.split(',')??PIPELINES;
  const backends=options.backends?.split(',')??BACKENDS;
  const threads=(options.threads??'1,6').split(',').map(Number), samples=Number(options.samples??5), verifySamples=Number(options['verify-samples']??20);
  if(pipelines.some(p=>!PIPELINES.includes(p))||backends.some(b=>!BACKENDS.includes(b))||threads.some(t=>![1,6].includes(t))||!Number.isInteger(samples)||samples<1||!Number.isInteger(verifySamples)||verifySamples<1)throw new Error('Invalid comparison options');
  const out=path.resolve(ROOT,options.out??`bench/results/${new Date().toISOString().slice(0,10)}-${runtime==='native'?'native-':''}comparison`);
  if(existsSync(path.join(out,'observations.json'))) {
    const previous=await json(path.join(out,'observations.json'));
    if((previous.metadata?.runtime??'wasm')!==runtime)throw new Error('Native and WASM observations require separate output directories');
  }
  await mkdir(out,{recursive:true});
  const source=await json(path.join(FIXTURES,pipelines[0],'comparison.json'));
  const report={metadata:{runtime,date:new Date().toISOString(),cpu:spawnSync('sysctl',['-n','machdep.cpu.brand_string'],{encoding:'utf8'}).stdout.trim(),logical_cores:os.availableParallelism(),memory_bytes:os.totalmem(),os:`${os.type()} ${os.release()}`,node:process.version,source:source.source,samples,threads,verify_samples:verifySamples,verify_warmups:1,
    proving_policy:runtime==='native'?'fresh actual native binary per sample; fixture, program and key initialization excluded from witness+prove; no pk_decode metric':'fresh Node/WASM process per sample, keys initialized outside combined witness+prove; no pk_decode metric',
    memory_method:runtime==='native'?'macOS /usr/bin/time -l directly wraps the native binary; whole native process peak footprint and RSS, including initialization and keys':'whole-process peak footprint and RSS; not browser linear-memory capacity',
    worker_policy:'1/6 are requested backend worker configurations, not a guarantee of total OS threads; requested_threads and actual_threads record reported configuration. Native MSM may use bounded nested worker pools.',
    circuit_stats_method:'Shared Barretenberg WASM chonkStats for structure only (no proving or verification); Rust counts from prepared native manifests',
    backend_notes:{chonk:'Exact PR Chonk app + registry/kernel/hiding fold',groth16:'Arkworks Groth16: shared ACIR application relations and private link equalities; canonical compressed proof. Native QAP streams the prepared r1cs.bin matrix plan through BufReader; WASM has a RAM-loaded plan.',provekit:'ProveKit low-level WHIR over the same merged R1CS; non-SPARK verifier retains full R1CS'},phone_measurements:false},circuits:{},runs:[],verifications:[]};
  for(const pipeline of pipelines) {
    const fixture=await json(path.join(FIXTURES,pipeline,'comparison.json'));
    report.circuits[pipeline]={fixture_sha256:createHash('sha256').update(JSON.stringify(fixture)).digest('hex'),public_fields:fixture.expected_public.length,kind:fixture.kind,algorithms:fixture.apps.map(a=>a.name)};
    if(backends.includes('chonk')) {
      const structure=measured(path.join(HERE,'bench.mjs'),['__stats',pipeline]);
      if(structure.status!=='ok')throw new Error(`Chonk stats: ${structure.error}`);
      report.circuits[pipeline].chonk=structure.circuits;
    }
    for(const backend of backends) {
      if(backend!=='chonk') {
        const bytes=await readFile(path.join(keyDirectory(backend,pipeline),'manifest.json'));
        const manifest=JSON.parse(bytes.toString('utf8'));
        // Keep native u64 scheme parameters in their original artifact, not a lossy JS roundtrip.
        report.circuits[pipeline][backend]={stats:manifest.stats,relation_id:manifest.relation_id??manifest.fixture_sha256,manifest_sha256:createHash('sha256').update(bytes).digest('hex')};
      }
      for(const threadCount of threads) for(let sample=1;sample<=samples;sample++) {
        process.stderr.write(`${pipeline} / ${backend} / ${runtime} / ${threadCount} worker budget / ${sample}/${samples}\n`);
        const row=runtime==='native' ? await nativeSample(backend,pipeline,threadCount)
          : backend==='chonk' ? measured(path.join(HERE,'bench.mjs'),['__sample',pipeline,String(threadCount)]) : measured(fileURLToPath(import.meta.url),['__sample',backend,pipeline,String(threadCount)]);
        if(runtime==='wasm'&&backend==='chonk'&&row.status==='ok') {
          const sum=name=>row.stages.filter(s=>s.stage===name).reduce((a,s)=>a+s.ms,0);
          row.prove_ms=sum('witness')+sum('witness_encode')+sum('prove'); row.verify_ms=sum('verify');
          row.initialization_ms=sum('bb_init'); row.proof_bytes=row.sizes.proof; row.compressed_proof_bytes=row.sizes.proofCompressed; row.verified=true; row.tamper_rejected=true;
        }
        report.runs.push({...row,runtime,pipeline,backend,threads:threadCount,requested_threads:threadCount,sample});
      }
      process.stderr.write(`${pipeline} / ${backend} / full-host verification\n`);
      const wasm=runtime==='wasm'?measured(fileURLToPath(import.meta.url),['__verify',backend,pipeline,String(os.availableParallelism()),String(verifySamples)]):null;
      const native=nativeVerify(backend,pipeline,verifySamples);
      report.verifications.push({runtime,pipeline,backend,wasm,native});
      await writeFile(path.join(out,'observations.json'),JSON.stringify(report,null,2));
    }
  }
  const csv=['pipeline,implementation,threads,sample,status,witness_prove_ms,verify_ms,peak_footprint_bytes,peak_rss_bytes,proof_bytes,compressed_proof_bytes,error,runtime,actual_threads'];
  const quote=value=>`"${String(value??'').replaceAll('"','""')}"`;
  for(const r of report.runs) csv.push([r.pipeline,r.backend,r.threads,r.sample,r.status,r.prove_ms,r.verify_ms,r.peak_footprint_bytes,r.peak_rss_bytes,r.proof_bytes,r.compressed_proof_bytes,r.error,r.runtime,r.actual_threads].map(quote).join(','));
  await writeFile(path.join(out,'timings.csv'),csv.join('\n')+'\n');
  await writeFile(path.join(out,'metadata.json'),JSON.stringify(report.metadata,null,2));
  await writeFile(path.join(out,'report.html'),renderReport(report));
  console.log(path.join(out,'report.html'));
}

const [command,...args]=process.argv.slice(2);
try {
  if(command==='__sample') console.log(JSON.stringify(await rustSample(args[0],args[1],Number(args[2]))));
  else if(command==='__verify') console.log(JSON.stringify(await wasmVerify(args[0],args[1],Number(args[2]),Number(args[3]))));
  else if(command==='run') {const options={};for(let i=0;i<args.length;i+=2)options[args[i].replace(/^--/,'')]=args[i+1];await run(options);}
  else throw new Error('usage: node compare.mjs run [--runtime wasm|native] [--samples 5] [--threads 1,6] [--verify-samples 20] [--pipelines IDS] [--backends chonk,groth16,provekit] [--out DIR]');
} catch(error) {console.log(JSON.stringify({error:error.stack??String(error),wasm_capacity_bytes:error.wasm_capacity_bytes??null}));process.exitCode=1;}
process.exit(process.exitCode??0);
