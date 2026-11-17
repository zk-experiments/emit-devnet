import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
export const CACHE = resolve(ROOT, 'bench/.cache');
export const PINS = {
  pr: 'ce610c62a51240d74a7fcf5a6b6644e2a7cea9ea',
  noir_zk: '0d022abf80cec1f2e28a7bc2008d0579af4ae141',
  emit_protocol: 'fcf30900219ca0382450fa6e6035bed944f0224a',
  noir: '1.0.0-rc.5', bb: '7.0.0-nightly.20261110',
};
export function run(command, args, options = {}) {
  console.log(`> ${command} ${args.join(' ')}`);
  const result = spawnSync(command, args, { cwd: ROOT, stdio: 'inherit', ...options });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} exited ${result.status ?? result.signal}`);
  return result;
}
export async function sources() {
  await mkdir(CACHE, { recursive: true });
  for (const [name, revision] of [['noir-zk', PINS.noir_zk], ['emit-protocol', PINS.emit_protocol]]) {
    const dest = resolve(CACHE, name);
    if (existsSync(resolve(dest, 'README.md'))) continue;
    await mkdir(dest, { recursive: true });
    const archive = resolve(CACHE, `${name}-${revision}.tar.gz`);
    run('curl', ['-fL', '--retry', '2', `https://codeload.github.com/zk-experiments/${name}/tar.gz/${revision}`, '-o', archive]);
    run('tar', ['-xzf', archive, '--strip-components=1', '-C', dest]);
  }
  await recordFolds();
}
async function recordFolds() {
  const path = resolve(CACHE, 'noir-zk/crates/noir-zk-backend/src/pipeline.rs');
  let source = await readFile(path, 'utf8');
  const marker = '// Emit comparison fixture recorder: outputs only; proof logic is unchanged.';
  if (source.includes(marker)) return;
  if (createHash('sha256').update(source).digest('hex') !== '27dedea5522c54dd34b393e90506556ae52c443b1165e1a48ad0a89d974219de') {
    throw new Error('Unexpected pinned noir-zk pipeline source');
  }
  const replace = (oldText, newText) => {
    if (source.split(oldText).length !== 2) throw new Error(`Unexpected recorder anchor: ${oldText}`);
    source = source.replace(oldText, newText);
  };
  replace('    witness: Vec<u8>,\n}', '    witness: Vec<u8>,\n    inputs: Vec<Field>,\n    input_toml: Option<String>,\n    outputs: Vec<Field>,\n}');
  replace('            label,\n            kind,\n            program,', '            label,\n            kind,\n            inputs: inputs.to_vec(),\n            input_toml: None,\n            outputs: solved.outputs.clone(),\n            program,');
  replace('        let solved = program.solve(program.inputs_from_toml(&step.toml)?)?;', '        let inputs = program.fields_from_toml(&step.toml)?;\n        let solved = program.solve(program.inputs_from_fields(&inputs)?)?;');
  replace('            kind: ChonkRole::App,\n            program,', '            kind: ChonkRole::App,\n            inputs,\n            input_toml: Some(step.toml.clone()),\n            outputs: solved.outputs.clone(),\n            program,');
  replace('        Ok((proof, public))', `${marker}
        if let Ok(root) = std::env::var("NOIR_ZK_BENCH_DUMP") {
            use base64::Engine as _;
            let name = std::env::var("NOIR_ZK_BENCH_CASE").unwrap_or_else(|_| self.pipeline.name.to_string());
            let dir = std::path::Path::new(&root).join(name);
            std::fs::create_dir_all(&dir).map_err(|e| Error::Artifact(e.to_string()))?;
            let mut records = Vec::new();
            for c in &self.circuits {
                let start = c.program.abi().field_count();
                let count = c.program.abi().return_field_count();
                let abi: serde_json::Value = serde_json::from_str(&self.artifacts.abi_json(c.label)?)
                    .map_err(|e| Error::Artifact(e.to_string()))?;
                records.push(serde_json::json!({
                    "name": c.label,
                    "kind": match c.kind { ChonkRole::App => 0, ChonkRole::Kernel => 1, ChonkRole::Hiding => 2 },
                    "bytecode": base64::engine::general_purpose::STANDARD.encode(c.program.bytecode()),
                    "vk": hex::encode(&c.vk),
                    "inputs": c.inputs.iter().map(hex).collect::<Vec<_>>(),
                    "artifact": {"abi": abi, "bytecode": self.artifacts.bytecode_b64(c.label)?},
                    "inputs_toml": c.input_toml,
                    "initial_witness": c.inputs.iter().enumerate().map(|(i, f)| (i, hex(f))).collect::<Vec<_>>(),
                    "output_witnesses": (start..start + count).collect::<Vec<_>>(),
                    "expected_outputs": c.outputs.iter().map(hex).collect::<Vec<_>>(),
                }));
            }
            for (file, value) in [("fold.json", serde_json::json!(records)), ("public.json", serde_json::json!(public.iter().map(hex).collect::<Vec<_>>()))] {
                std::fs::write(dir.join(file), serde_json::to_vec(&value).map_err(|e| Error::Artifact(e.to_string()))?)
                    .map_err(|e| Error::Artifact(e.to_string()))?;
            }
            std::fs::write(dir.join("proof.bin"), proof.to_bytes()).map_err(|e| Error::Artifact(e.to_string()))?;
        }
        Ok((proof, public))`);
  await writeFile(path, source);
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await sources();
