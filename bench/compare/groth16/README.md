# Arkworks Groth16 comparison backend

This is Arkworks Groth16/BN254, not a Rarimo implementation. The owned translator,
gadgets, constants and behavioral tests reuse the read-only prior
`emit-devnet/experiments/groth16-passport` experiment, upgraded to Noir rc.5.
The source fixture decides the actual passport/age relation; no signature-only or
toy substitute is selected. Registration validation requires all four ordered
apps, all three private links and exactly the six common public outputs. The
same synthesizer supports the common one-app age fixture.

Output witnesses must match the flattened ABI input-count/return-count layout.
For `return_data` returns, the ordered witnesses must also match the unique,
immutable ACIR `ReturnData` block; ordinary public returns are checked against
ACIR `return_values`. Missing, reordered or mixed return metadata is rejected.

## Build

Requires Rust 1.94+, `wasm32-unknown-unknown`, Node, and wasm-bindgen CLI **0.2.114**.
The threaded build uses nightly-2026-03-04 and its `rust-src` component by default.
`WASM_BINDGEN` can name a local CLI binary and `RUST_NIGHTLY` can override the pin.
From the repository root:

```sh
rustup target add wasm32-unknown-unknown
rustup component add rust-src --toolchain nightly-2026-03-04
cargo install wasm-bindgen-cli --version 0.2.114 --locked
node bench/compare/groth16/build.mjs native
node bench/compare/groth16/build.mjs wasm
node bench/compare/groth16/build.mjs threads
```

The native binary is `bench/compare/groth16/target/release/passport-groth16`.
Web modules are `groth16/pkg-single/passport_groth16.js` and
`groth16/pkg-threads/passport_groth16.js`, with their matching
`passport_groth16_bg.wasm`. Keep threaded `snippets/` and `worker-runtime.mjs`
beside the generated module. Browser threads require COOP/COEP cross-origin
isolation. The build script adapts Rayon's generated JS worker transport and the
wasm-only native-subpool scheduler described below; cryptographic math is unchanged.
Node uses real `worker_threads`, browsers use real module Workers. The single
build does not enable Rayon.

All modes use upstream Arkworks 0.6 WNAF MSM arithmetic for G1 and G2.
`vendor.mjs` verifies the pinned crate archive SHA-256, retains both upstream
licenses and records provenance in generated `vendor/ark-ec-0.6.0/SCHEDULER-PATCH.json`.
Its guarded patch executes the existing WNAF closure on the global Rayon pool
on wasm32 instead of creating unsupported native subpools; the native branch is
unchanged. Every build rejects upstream anchor or generated-source mismatches.
The build helper generates this overlay automatically; use `node build.mjs vendor`
before direct Cargo commands in a fresh checkout. The session's thread count is
read from Rust's actual Rayon pool, not echoed from the requested JS option.

## Prepare native artifacts

```sh
BIN=bench/compare/groth16/target/release/passport-groth16
PIPELINE=age_verify # or either identity_register_* pipeline
FIXTURE=bench/fixtures/$PIPELINE/comparison.json
KEYS=bench/fixtures/$PIPELINE/groth16
$BIN setup "$FIXTURE" "$KEYS"
$BIN prove "$FIXTURE" "$KEYS" "$KEYS/proof.bin"
$BIN verify "$KEYS/vk.bin" "$KEYS/public.json" "$KEYS/proof.bin" 20
```

Setup uses fresh OS entropy and is explicitly a **local test setup**, not a
production ceremony. Registration preparation is memory-intensive. Prepare one
case at a time; the script never silently reduces the relation.

`manifest.json` records backend/compiler IDs, relation fingerprint, exact sizes,
constraint/witness/public counts, FFT domain, query-memory estimates, filenames
and SHA-256 hashes. Artifact names and encodings:

- `pk.bin`, `vk.bin`: checked Arkworks canonical point-compressed serialization.
- `r1cs.bin`: streaming sparse A/B/C plan, `PG16R1C1`, LE-u32 dimensions/row
  lengths/indices; coefficient tags 0=one, 1=minus-one, 2=canonical Fr bytes.
- `public.json`: ordered canonical 32-byte big-endian hex fields.
- `proof.bin`: canonical point-compressed BN254 Groth16 proof (128 bytes).
  Actual uncompressed group serialization is 256 bytes, exposed separately;
  no gzip-as-group-compression claim or extra compression operation is made.

Native `verify` loads/decodes VK, proof and the expected public statement once,
prepares the VK outside timing, warms once, and returns `verify_samples_ms`,
`verify_median_ms`, `warmup_ms` and actual Rayon `threads`. The optional last
argument is the measured sample count (default 20). With the parallel build,
Rayon defaults to available host cores; `RAYON_NUM_THREADS` explicitly overrides.
No proving key is loaded by this command.

## Device API

`bench/compare/groth16.mjs` exports:

- `prepare({fixture, assets, threads})`, assets `{manifest,pk,vk,r1cs,wasm}`.
- `prepareVerifier({fixture, assets, threads})`, assets `{manifest,vk,wasm}` only.

Every asset is a `Uint8Array`; `manifest` contains UTF-8 `manifest.json`. Choose
WASM matching single (`threads=1`) or threaded (`threads>1`) module. `fixture`
can be the common JSON object or its JSON text. Sessions expose `verify`,
`verifyPublic` (negative tests), `proofBytes`, `uncompressedProofBytes`, `stats`,
`memoryBytes` and async `dispose`; only proving sessions expose `prove`.
Verification always binds `fixture.expected_public`; it never trusts public
values supplied alongside a proof. `stats.proof_encoding` identifies the already
point-compressed transport and `stats.compression` is null.

The prove timer includes fresh ACVM execution, Arkworks assignment generation,
streamed QAP evaluation and randomized Groth16 proving. Only ABI input witnesses
are accepted from the fixture; saved internal assignments are rejected. Each
app's solved ACVM map is dropped immediately after synthesis. Witness-only
synthesis stores no constraints/matrices; Arkworks does retain evaluated
symbolic LCs until the assignment is extracted. Matrix rows are read and
evaluated directly, not deserialized into runtime matrices. PK and plan assets
are copied into WASM in bounded 1 MiB chunks, never as full extra encoded copies.

Use a fresh disposable Worker/process for each benchmark sample. `dispose`
frees the session/key and Rayon workers; generated wasm-bindgen modules retain
their linear-memory instance until their JS realm is terminated. The manifest's
`wasm32_lower_bound_bytes` includes decoded queries, two live QAP vectors and the
assignment. A bound at/above the wasm32 limit rejects proving before decoding
keys. A smaller bound **does not establish feasibility**: ACVM/LC storage,
FFT/MSM scratch and allocator overhead still have to fit. Verification-only
sessions do not load the PK/plan or apply the prover memory bound. Report actual
allocation failures as resource blockers, not successful/shortened workloads.

## Final checks (run by integration owner)

```sh
cargo test --manifest-path bench/compare/groth16/Cargo.toml --lib --features parallel
# After setup and native proof generation above:
node bench/compare/groth16/check-wasm.mjs verify "$FIXTURE" "$KEYS" "$KEYS/proof.bin" 1
node bench/compare/groth16/check-wasm.mjs verify "$FIXTURE" "$KEYS" "$KEYS/proof.bin" 6
node bench/compare/groth16/check-wasm.mjs prove "$FIXTURE" "$KEYS" "$KEYS/wasm-proof.bin" 1
$BIN verify "$KEYS/vk.bin" "$KEYS/public.json" "$KEYS/wasm-proof.bin" 20
```

Repeat proving with 6 threads only where the full relation fits. The Rust tests
cover all three private links, six public claims, memory/range/logic/hash gadget
binding, canonical fields, fresh ACVM assignment generation, saved-witness
rejection, setup/assignment agreement, streamed reduction equivalence with
upstream Arkworks, real proof verification and changed/truncated/corrupt inputs.
The WASM check exercises real native/WASM interop and negative public binding.
