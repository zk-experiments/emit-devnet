import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { ROOT, CACHE, run } from './bootstrap.mjs';

const options={};for(let i=2;i<process.argv.length;i+=2)options[process.argv[i].replace(/^--/,'')]=process.argv[i+1];
const backends=(options.backends??'groth16,provekit').split(',');
const pipelines=(options.pipelines??'identity_register_de_bp384_bp256,identity_register_us_rsa4096_rsa2048,age_verify').split(',');
if(backends.some(b=>!['groth16','provekit'].includes(b))||pipelines.some(p=>!['identity_register_de_bp384_bp256','identity_register_us_rsa4096_rsa2048','age_verify'].includes(p)))throw new Error('Unknown backend/pipeline');
const bindgen=resolve(CACHE,'bindgen-0.2.114/wasm-bindgen');
const env={...process.env,RUST_NIGHTLY:process.env.RUST_NIGHTLY??'nightly-2026-03-04'};
if(existsSync(bindgen)){env.WASM_BINDGEN=bindgen;env.PATH=`${resolve(CACHE,'bindgen-0.2.114')}:${env.PATH}`;}
for(const backend of backends) run(process.execPath,[`bench/compare/${backend}/build.mjs`,'all'],{env});
// Large registration keys are prepared serially, not concurrently with measurements.
for(const pipeline of pipelines) for(const backend of backends) {
  const fixture=resolve(ROOT,`bench/fixtures/${pipeline}/comparison.json`);
  const output=resolve(ROOT,`bench/artifacts/${backend}/${pipeline}`), proof=resolve(output,'proof-native.bin');
  if(!existsSync(fixture))throw new Error(`Missing ${fixture}; run node bench/compare/fixtures.mjs first`);
  if(backend==='groth16') {
    const binary=resolve(ROOT,'bench/compare/groth16/target/release/passport-groth16');
    run(binary,['setup',fixture,output],{env:{...env,RAYON_NUM_THREADS:'6'}});
    run(binary,['prove',fixture,output,proof],{env:{...env,RAYON_NUM_THREADS:'6'}});
    run(binary,['verify',resolve(output,'vk.bin'),resolve(output,'public.json'),proof,'1'],{env});
  } else {
    const binary=resolve(ROOT,'bench/compare/provekit/target/native/release/passport-provekit');
    run(binary,['prepare',fixture,output,'6'],{env});
    run(binary,['prove',fixture,output,proof,'6'],{env});
    run(binary,['verify-once',fixture,output,proof,'6'],{env});
  }
}
