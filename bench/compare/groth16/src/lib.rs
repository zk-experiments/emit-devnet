pub mod circuit;
pub mod engine;
pub mod fixture;
mod gadgets;
mod poseidon2_constants;

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
mod wasm;

#[cfg(all(feature = "threads", target_arch = "wasm32"))]
pub use wasm_bindgen_rayon::init_thread_pool;
