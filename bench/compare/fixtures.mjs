import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { ROOT, CACHE, PINS, sources, run } from './bootstrap.mjs';

await sources();
const nargo = process.env.NARGO ?? (existsSync(resolve(CACHE,'tools/nargo')) ? resolve(CACHE,'tools/nargo') : 'nargo');
const version = run(nargo,['--version'],{stdio:'pipe',encoding:'utf8'}).stdout;
if(!version.includes(PINS.noir)) throw new Error(`Expected nargo ${PINS.noir}, got ${version}`);
run(nargo,['compile','--program-dir','bench/compare/noir/age_verify']);
run('cargo',['+stable','build','--release','--locked','--manifest-path','bench/.cache/noir-zk/Cargo.toml','-p','noir-zk-cli']);
run(resolve(CACHE,'noir-zk/target/release/noir-zk'),['freeze','--target','bench/compare/noir/age_verify/target','--out','bench/compare/fixtures','--assets','bench/compare/fixtures/assets','--library','passport-comparison@0.1.0']);
run('cargo',['+stable','build','--release','--locked','--manifest-path','bench/compare/fixtures/Cargo.toml']);
const output=resolve(ROOT,'bench/fixtures'), binary=resolve(ROOT,'bench/compare/fixtures/target/release/passport-comparison-fixtures');
for(const name of ['de_bp384_bp256','us_rsa4096_rsa2048']) {
  run(binary,['register',name,output],{env:{...process.env,NOIR_ZK_BENCH_DUMP:output,NOIR_ZK_BENCH_CASE:`identity_register_${name}`}});
}
run(binary,['age',output],{env:{...process.env,NOIR_ZK_BENCH_DUMP:output,NOIR_ZK_BENCH_CASE:'age_verify'}});
console.log(output);
