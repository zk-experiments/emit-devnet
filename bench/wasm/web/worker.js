import { observeWasmMemory } from './memory.js';
const memory=observeWasmMemory();
const decode=bytes=>JSON.parse(new TextDecoder().decode(bytes));
const fromBase64=text=>Uint8Array.from(atob(text),c=>c.charCodeAt(0));
const fromHex=text=>Uint8Array.from(text.match(/../g),byte=>parseInt(byte,16));
async function transform(bytes,compression) {
  const stream=new Blob([bytes]).stream().pipeThrough(compression);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
async function fetchAsset(asset,base) {
  const url=new URL(asset.path,base);
  if(url.origin!==location.origin||!url.pathname.startsWith(new URL(base).pathname))throw new Error('Asset escapes application directory');
  const response=await fetch(url,{redirect:'error'});
  if(!response.ok)throw new Error(`HTTP ${response.status}: ${asset.path}`);
  const bytes=new Uint8Array(await response.arrayBuffer());
  if(bytes.length!==asset.bytes)throw new Error(`Size mismatch: ${asset.path}`);
  const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');
  if(hash!==asset.sha256)throw new Error(`SHA-256 mismatch: ${asset.path}`);
  return bytes;
}
const phase=label=>postMessage({type:'phase',label});
const median=values=>{const a=[...values].sort((a,b)=>a-b),m=Math.floor(a.length/2);return a.length%2?a[m]:(a[m-1]+a[m])/2;};

async function chonk(entry,threads,base,verifyOnly,count) {
  phase('Loading Chonk circuits and runtime');
  const start=performance.now();
  const [foldBytes,publicBytes,nativeBytes]=await Promise.all(['fold','public','native_proof'].map(role=>fetchAsset(entry.assets[role],base)));
  const steps=decode(foldBytes),expected=decode(publicBytes);
  const {Barretenberg,BackendType,flattenChonkProofFields}=await import('@aztec-foundation/bb.js');
  const api=await Barretenberg.new({backend:BackendType.Wasm,threads});
  await api.initSRSChonk();
  const vk=fromHex(steps.at(-1).vk);
  try {
    if(verifyOnly) {
      const proof=Array.from({length:nativeBytes.length/32},(_,i)=>nativeBytes.subarray(i*32,(i+1)*32));
      if(!expected.every((value,i)=>BigInt(value)===BigInt('0x'+Array.from(proof[i],b=>b.toString(16).padStart(2,'0')).join(''))))throw new Error('Full-device verification proof has the wrong public statement');
      const verify=async()=>{if(!(await api.chonkVerifyFromFields({proof,vk})).valid)throw new Error('Chonk proof rejected');};
      await verify(); const samples=[];
      for(let i=0;i<count;i++){const t=performance.now();await verify();samples.push(performance.now()-t);}
      return {verify_samples_ms:samples,verify_median_ms:median(samples),warmups:1,threads,proof_transport_bytes:nativeBytes.length};
    }
    const acvm=await import('@noir-lang/acvm_js'); await acvm.default();
    const initializationMs=performance.now()-start;
    phase('Generating Chonk witnesses and folded proof');
    const begin=performance.now(), witnesses=[];
    for(const step of steps) {
      step.bytecodeRaw=fromBase64(step.bytecode);
      const program=await transform(step.bytecodeRaw,new CompressionStream('gzip'));
      const solved=await acvm.executeCircuit(program,new Map(step.inputs.map((value,i)=>[i,value])),async()=>{throw new Error('Unexpected foreign call');});
      witnesses.push(await transform(acvm.compressWitnessStack([{index:0,witness:solved}]),new DecompressionStream('gzip')));
    }
    await api.chonkStart({kinds:Uint8Array.from(steps.map(s=>s.kind))});
    for(const [i,step] of steps.entries()) {
      await api.chonkLoad({circuit:{name:step.name,bytecode:step.bytecodeRaw,verificationKey:fromHex(step.vk)},kind:step.kind});
      await api.chonkAccumulate({witness:witnesses[i]});
    }
    const {proof}=await api.chonkProve({}), proved=performance.now(), observed=memory();
    phase('Verifying Chonk proof');
    const verifyStart=performance.now();
    if(!(await api.chonkVerify({proof,vk})).valid)throw new Error('Chonk proof rejected');
    const verifyMs=performance.now()-verifyStart;
    const flat=flattenChonkProofFields(proof);
    if(!expected.every((value,i)=>BigInt(value)===BigInt('0x'+Array.from(flat[i],b=>b.toString(16).padStart(2,'0')).join(''))))throw new Error('Chonk public statement mismatch');
    const compressed=(await api.chonkCompressProof({proof})).compressedProof;
    return {initialization_ms:initializationMs,prove_ms:proved-begin,verify_ms:verifyMs,verified:true,proof_bytes:flat.length*32,compressed_proof_bytes:compressed.length,wasm_capacity_bytes:observed.bytes,memory:observed,actual_threads:threads};
  } finally {await api.destroy();}
}

self.onmessage=async({data})=>{
  const {entry,threads,base,verifyOnly=false,count=20}=data;
  let session;
  try {
    if(!crypto.subtle)throw new Error('HTTPS or localhost is required');
    if(threads>1&&(!crossOriginIsolated||typeof SharedArrayBuffer==='undefined'))throw new Error('Multiple threads require cross-origin isolation; no single-thread fallback is used');
    let result;
    if(entry.backend==='chonk')result=await chonk(entry,threads,base,verifyOnly,count);
    else {
      phase('Loading fixture, keys and WASM');
      const start=performance.now();
      const fixture=decode(await fetchAsset(entry.fixture,base));
      const assets={};
      const roles=entry.backend==='groth16'?(verifyOnly?['manifest','vk']:['manifest','pk','vk','r1cs']):['manifest','r1cs'];
      for(const role of roles)assets[role]=await fetchAsset(entry.assets[role],base);
      assets.wasm=await fetchAsset(entry.runtimes[threads===1?'single':'threads'],base);
      const moduleURL=new URL(`adapters/${entry.backend}.mjs`,base).href;
      const adapter=await import(/* @vite-ignore */ moduleURL);
      session=await (verifyOnly?adapter.prepareVerifier:adapter.prepare)({fixture,assets,threads});
      const initializationMs=performance.now()-start;
      if(verifyOnly) {
        phase('Verifying with the full device thread count');
        const proof=await fetchAsset(entry.assets.native_proof,base);
        if(await session.verify(proof)!==true)throw new Error('Warm-up verification rejected');
        const samples=[];
        for(let i=0;i<count;i++){const t=performance.now();if(await session.verify(proof)!==true)throw new Error('Verification rejected');samples.push(performance.now()-t);}
        result={verify_samples_ms:samples,verify_median_ms:median(samples),warmups:1,threads,proof_transport_bytes:proof.length};
      } else {
        phase('Generating witness and proof');
        const begin=performance.now(),proof=await session.prove(),proved=performance.now(),observed=memory();
        phase('Verifying proof');const verifyStart=performance.now();
        if(await session.verify(proof)!==true)throw new Error('Proof rejected');
        const verifyMs=performance.now()-verifyStart;
        const bytes=session.proofBytes(proof), raw=session.uncompressedProofBytes?.(proof);
        result={initialization_ms:initializationMs,prove_ms:proved-begin,verify_ms:verifyMs,verified:true,proof_bytes:raw instanceof Uint8Array?raw.length:bytes.length,compressed_proof_bytes:raw instanceof Uint8Array?bytes.length:null,stats:session.stats,wasm_capacity_bytes:observed.bytes,memory:observed,actual_threads:session.threads??threads};
      }
    }
    postMessage({type:'result',result:{...result,pipeline:entry.pipeline,backend:entry.backend,threads,status:'ok'}});
  } catch(error) {postMessage({type:'result',result:{pipeline:entry.pipeline,backend:entry.backend,threads,status:'error',error:error.stack??String(error),wasm_capacity_bytes:error.wasm_capacity_bytes??memory().bytes}});}
  finally {await session?.dispose?.();self.close();}
};
