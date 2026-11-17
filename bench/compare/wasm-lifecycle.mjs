// A trap can leave wasm-bindgen's dynamic Rust borrow set. Do not enter that
// instance again, including its destructors; the owner must terminate the realm.
export function callRust(context, operation) {
  if (context.poisoned) throw context.poisoned;
  try {
    return operation();
  } catch (error) {
    if (error instanceof WebAssembly.RuntimeError) {
      context.poisoned = error;
      // Read the live memory after the failure, not its initialization size.
      // Diagnostics must never replace the original trap if annotation fails.
      try { error.wasm_capacity_bytes = context.wasm.memory.buffer.byteLength; } catch {}
    }
    throw error;
  }
}

export function freeRust(context, value) {
  if (context.poisoned) return;
  callRust(context, () => value.free());
  context.resources.delete(value);
}
