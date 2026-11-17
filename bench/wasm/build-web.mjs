import { build } from 'vite';
import { cp, mkdir, readFile, writeFile, readdir } from 'node:fs/promises';
import { constants, createReadStream, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const here=path.dirname(fileURLToPath(import.meta.url)),root=path.resolve(here,'../..'),out=path.join(root,'bench/web-dist');
const pipelines=(process.env.PIPELINES??'identity_register_de_bp384_bp256,identity_register_us_rsa4096_rsa2048,age_verify').split(',');
const backends=['chonk','groth16','provekit'];
await build({root:path.join(here,'web'),base:'./',publicDir:false,build:{outDir:out,emptyOutDir:true,minify:false},worker:{format:'es'},optimizeDeps:{exclude:['@aztec-foundation/bb.js','@aztec-foundation/bb.js-api']}});
async function stage(source,relative){const destination=path.join(out,relative);await mkdir(path.dirname(destination),{recursive:true});await cp(source,destination,{mode:constants.COPYFILE_FICLONE});const hash=createHash('sha256');let bytes=0;for await(const chunk of createReadStream(destination)){hash.update(chunk);bytes+=chunk.length;}return{path:relative,bytes,sha256:hash.digest('hex')};}
const manifest={schema_version:1,source:null,circuits:{},entries:[],reference:false,native_reference:false};
await mkdir(path.join(out,'adapters'),{recursive:true});
await cp(path.join(root,'bench/compare/wasm-lifecycle.mjs'),path.join(out,'adapters/wasm-lifecycle.mjs'));
for(const backend of ['groth16','provekit']){
  await cp(path.join(root,`bench/compare/${backend}.mjs`),path.join(out,`adapters/${backend}.mjs`));
  if(backend==='groth16')for(const mode of ['single','threads'])await cp(path.join(root,`bench/compare/groth16/pkg-${mode}`),path.join(out,`adapters/groth16/pkg-${mode}`),{recursive:true,mode:constants.COPYFILE_FICLONE});
  else await cp(path.join(root,'bench/compare/provekit/pkg'),path.join(out,'adapters/provekit/pkg'),{recursive:true,mode:constants.COPYFILE_FICLONE});
}
for(const pipeline of pipelines){
  const fixtureDir=path.join(root,'bench/fixtures',pipeline);
  const fixture=JSON.parse(await readFile(path.join(fixtureDir,'comparison.json'),'utf8'));
  manifest.source??=fixture.source;
  const fixtureAsset=await stage(path.join(fixtureDir,'comparison.json'),`fixtures/${pipeline}/comparison.json`);
  const stats=spawnSync(process.execPath,[path.join(here,'bench.mjs'),'__stats',pipeline],{encoding:'utf8',maxBuffer:1<<26});
  if(stats.status!==0)throw new Error(stats.stderr);
  const structure=JSON.parse(stats.stdout.trim().split('\n').at(-1)).circuits;
  manifest.circuits[pipeline]={kind:fixture.kind,public_fields:fixture.expected_public.length,chonk:structure,algorithms:fixture.apps.map(a=>a.name)};
  for(const backend of backends){
    const entry={pipeline,backend,fixture:fixtureAsset,assets:{}};
    if(backend==='chonk'){
      for(const [role,file] of Object.entries({fold:'fold.json',public:'public.json',native_proof:'proof.bin'}))entry.assets[role]=await stage(path.join(fixtureDir,file),`fixtures/${pipeline}/${file}`);
    }else{
      const dir=path.join(root,'bench/artifacts',backend,pipeline);
      const files=backend==='groth16'?{manifest:'manifest.json',pk:'pk.bin',vk:'vk.bin',r1cs:'r1cs.bin',native_proof:'proof-native.bin'}:{manifest:'manifest.json',r1cs:'r1cs.bin',native_proof:'proof-native.bin'};
      for(const [role,file] of Object.entries(files))entry.assets[role]=await stage(path.join(dir,file),`artifacts/${backend}/${pipeline}/${file}`);
      const nativeManifest=JSON.parse(await readFile(path.join(dir,'manifest.json'),'utf8'));
      manifest.circuits[pipeline][backend]={stats:nativeManifest.stats,relation_id:nativeManifest.relation_id??nativeManifest.fixture_sha256,manifest_sha256:entry.assets.manifest.sha256};
      entry.runtimes={};
      for(const mode of ['single','threads']){
        const relative=backend==='groth16'?`adapters/groth16/pkg-${mode}/passport_groth16_bg.wasm`:`adapters/provekit/pkg/${mode}/passport_provekit_bg.wasm`;
        const hash=createHash('sha256');let bytes=0;for await(const chunk of createReadStream(path.join(out,relative))){bytes+=chunk.length;hash.update(chunk);}entry.runtimes[mode]={path:relative,bytes,sha256:hash.digest('hex')};
      }
    }
    manifest.entries.push(entry);
  }
}
const results=path.join(root,'bench/results');
for(const name of (await readdir(results)).filter(n=>n.endsWith('-comparison')).sort().reverse()){
  const directory=path.join(results,name);
  if(!existsSync(path.join(directory,'report.html'))||!existsSync(path.join(directory,'metadata.json')))continue;
  const metadata=JSON.parse(await readFile(path.join(directory,'metadata.json'),'utf8'));
  const native=name.endsWith('-native-comparison'),flag=native?'native_reference':'reference';
  if((metadata.runtime??'wasm')!==(native?'native':'wasm')||manifest[flag])continue;
  await cp(directory,path.join(out,native?'reference-native':'reference'),{recursive:true,mode:constants.COPYFILE_FICLONE});
  manifest[flag]=true;
  if(manifest.reference&&manifest.native_reference)break;
}
await mkdir(path.join(out,'licenses'),{recursive:true});
await cp(path.join(root,'LICENSE'),path.join(out,'licenses/emit-devnet-MIT.txt'));
await writeFile(path.join(out,'manifest.json'),JSON.stringify(manifest,null,2));
console.log(`Built ${manifest.entries.length} matched browser workloads at ${out}`);
