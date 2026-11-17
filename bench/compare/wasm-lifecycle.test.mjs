import assert from 'node:assert/strict';
import test from 'node:test';
import { callRust, freeRust } from './wasm-lifecycle.mjs';

test('real WASM trap poisons the realm and cleanup preserves the original error', async () => {
  const { instance } = await WebAssembly.instantiate(Uint8Array.from([
    0,97,115,109,1,0,0,0, 1,4,1,96,0,0, 3,2,1,0,
    7,8,1,4,116,114,97,112,0,0, 10,5,1,3,0,0,11,
  ]));
  const memory = new WebAssembly.Memory({ initial: 1, maximum: 2 });
  const context = { wasm: { memory }, poisoned: null, resources: new Set() };
  let frees = 0;
  const borrowed = { free() { frees++; throw new Error('borrowed destructor must never run'); } };
  const other = { free() { frees++; } };
  context.resources.add(borrowed).add(other);
  let original;
  try { callRust(context, () => { memory.grow(1); instance.exports.trap(); }); }
  catch (error) { original = error; }
  assert.ok(original instanceof WebAssembly.RuntimeError);
  assert.equal(context.poisoned, original);
  assert.equal(original.wasm_capacity_bytes, 131072, 'report actual grown capacity at the trap');
  freeRust(context, borrowed);
  freeRust(context, other);
  assert.equal(frees, 0);
  assert.equal(context.resources.size, 2, 'retain handles so finalizers cannot enter trapped Rust');
  assert.throws(() => callRust(context, () => assert.fail('poisoned realm reentered')), error => error === original);
});

test('ordinary proof rejection and JsError do not poison or leak a healthy realm', () => {
  const context = { poisoned: null, resources: new Set() };
  assert.equal(callRust(context, () => false), false);
  const invalid = new Error('invalid proof');
  assert.throws(() => callRust(context, () => { throw invalid; }), error => error === invalid);
  assert.equal(context.poisoned, null);
  let frees = 0;
  const value = { free() { frees++; } };
  context.resources.add(value);
  freeRust(context, value);
  assert.equal(frees, 1);
  assert.equal(context.resources.size, 0);
});
