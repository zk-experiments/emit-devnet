# Matched passport implementation comparison

Local integration based on Emit devnet PR #3, head `ce610c62a51240d74a7fcf5a6b6644e2a7cea9ea`. The original `emit-devnet` checkout and the standalone `zk-passports` demo are unchanged. No pushes are part of this workflow.

## Scope

The two registration cases reuse the PR's **exact application bytecode, passport fixtures, three private cross-stage link equalities and six public outputs**:

- `identity_register_de_bp384_bp256`: CSCA→DSC Brainpool P384/SHA-384; DSC→SOD Brainpool P256/SHA-256; document SHA-256 eContent / SHA-512 DG1; Emit registration leaf.
- `identity_register_us_rsa4096_rsa2048`: RSA-4096/SHA-256 DSC; RSA-2048/SHA-256 SOD; document SHA-256 eContent / DG1; the same Emit registration leaf.
- `age_verify`: replaces the member/payment comparison. It uses the actual US registration leaf in an Emit depth-32 identity tree, checks expiry and age ≥18 on 2026-09-27, and publishes a context-bound holder tag. This is a new common circuit, not `member_resolve` or `member_transfer`. MRZ two-digit birth years select the most recent non-future birthday (ages0–99); February29 anniversaries are March1 in non-leap years.

Implementations:

- **Chonk / Barretenberg**: PR app/registry/kernel/hiding fold, pinned to bb `7.0.0-nightly.20261110` and ACVM `1.0.0-rc.5`.
- **Groth16 / Arkworks**: rc.5 ACIR→R1CS translation adapted from the existing local passport experiment; all registration apps and links in one Groth16 relation. This is **not Rarimo/Circom**. The old Rarimo statement was not equivalent to the PR's registration chain.
- **ProveKit / WHIR**: pinned revision `893f6d5866d52124e12c4a90a71c0f4d625f083b`, using the same merged R1CS and low-level WHIR with hiding commitments. This avoids substituting beta.26 circuit semantics for the PR's rc.5 artifacts. It is **not** ProveKit's optimized Noir frontend; its non-SPARK verification key includes the full R1CS. Results characterize this adapter, not an optimal ProveKit circuit lowering.

Chonk has additional generic registry/hiding kernels; the alternatives fix the selected applications in their relation and enforce the same application links directly. Public claims are checked against the common fixture. Chonk gate counts and R1CS constraint counts are different units.

## Reproduce

Requirements: Node22.12+, Rust/stable, nightly-2026-03-04 with `rust-src` and `wasm32-unknown-unknown`, nargo `1.0.0-rc.5`, wasm-bindgen CLI `0.2.114`. Use the pinned versions; native and WASM keys must agree. Provision the SRS as in the PR (`scripts/srs.sh`); existing `~/.bb-crs` is reused and checked by noir-zk.

```sh
cd bench/wasm
npm ci --ignore-scripts
cd ../..

# Downloads pinned source snapshots, compiles/freezes the common age app,
# records real native folds and emits common comparison.json for all three cases.
NARGO=/path/to/nargo node bench/compare/fixtures.mjs

# Large keys: prepare serially, with enough RAM and disk space.
# WASM_BINDGEN and RUST_NIGHTLY can select the pinned installed tools.
node bench/compare/prepare.mjs

# Same summary columns as the reference: 1/6-thread proving and verification,
# process footprint, full-host WASM/native verification, proof sizes.
# Full-host verification is one warm-up followed by 20 measured calls.
cd bench/wasm
node compare.mjs run --samples 5 --threads 1,6 --verify-samples 20
npm run build:web
npm run serve
```

The static browser demo is served on `http://localhost:8090`; use trusted HTTPS on a physical phone. Node reports are under `bench/results/<date>-comparison/{report.html,observations.json,timings.csv,metadata.json}`. A generated host report is linked separately from live device measurements; native timings are never presented as phone measurements.

For a focused check, select `--pipelines age_verify --samples 1` in the runner. `PIPELINES=age_verify npm run build:web` builds just that prepared workload for development; omit it for the complete demo. `node bench/wasm/smoke.mjs` exercises all three age implementations at 1/6 threads, full-device verification, export and responsive layout against the running server.

## Measurement boundaries

- Witness + prove includes fresh ACVM execution and proving. Groth16 also synthesizes the assignment and evaluates the streamed QAP; it does not load saved internal witnesses. Runtime/key preparation is outside this timer. No separate `pk_decode` measurement or new key-validation instrumentation is introduced.
- Each proving sample is a fresh Node/WASM process (or browser Worker). Full-host verification loads keys/proof once, warms once, then measures 20 verifies, using the same native-produced proof in WASM and native runtimes.
- Node memory is whole-process peak `phys_footprint` and RSS from macOS `/usr/bin/time -l`, including Node, key loading and runtime. Browser memory is only observed WASM linear-memory capacity and explicitly uses a different label; it excludes JS/native overhead and unobserved nested-worker memory. They are not interchangeable.
- Proof sizes use actual serialization. Chonk provides its native field representation and point-compressed form. Groth16 reports canonical uncompressed/compressed encodings. WHIR uses its native postcard transport and no extra compression API; no gzip value is relabelled as curve compression. When proving fails, the summary can still show the size of the native-generated proof accepted by the independent verifier.
- Chonk includes pipeline/public fields in its proof. The Groth16/WHIR public claims are external:192 bytes for registration,160 for age. Key sizes and circuit artifact bytes remain in metadata.
- wasm32 is a hard resource limit. Groth16 records a lower bound for decoded queries/QAP/assignment, but ACVM, symbolic linear combinations, FFT/MSM scratch and allocation overhead still need room. Actual resource failures are retained as failures, not zero times or smaller replacement circuits. Native verification can still be measured independently of whether on-device proving fits.
- The circuit/input artifacts are identical across implementations; arithmetization, proof composition, key sizes and verification algorithms differ. Do not treat the numbers as a general proof-system ranking or infer phone performance from this desktop host.

Only synthetic passport fixtures and local test Groth16 setup are used. This is not a government trust registry, a production ceremony or an on-chain registration deployment.

## Source layout

`fixtures/` is the native recorder/age registry tool; `noir/age_verify/` is the common age statement. `groth16/` and `provekit/` contain independent native/WASM backend builds and their interoperability checks. `../wasm/compare.mjs` runs isolated process measurements; `report-view.mjs` shares the summary layout with the browser demo. Generated sources, keys, fixtures, runtimes and browser distributions stay outside tracked source via ignore rules. Cargo/npm lockfiles are retained for reproducibility.

## Cross-target transcript portability

The pinned Spongefish SHA-256 sponge encodes its squeeze counters using `usize`, which changes the transcript between native64 and wasm32. `provekit/src/portable.rs` fixes those counters to u64, preserving the upstream native64 protocol. Upstream golden-vector and streaming/ratchet parity tests cover the adaptation; native verification of actual single- and six-thread WASM age proofs passed. The registration circuits, R1CS and native setup artifacts are unchanged by this portability fix.

## Groth16 worker portability

Arkworks 0.6's wNAF MSM creates a nested native thread pool, which cannot start inside a browser Rayon worker. `groth16/vendor.mjs` generates a checksum-pinned source overlay that uses the existing global worker pool on WASM only. It does not replace the MSM algorithm or change native arithmetic. Both single- and six-thread WASM age proofs passed verification, including native verification of the six-thread proof; 17 targeted native relation/gadget tests passed with the parallel feature.

## Recorded local checks

The local host is an Apple M5 Pro with 18 logical cores and 48 GiB RAM, not the screenshot's 14-thread machine. Saved observations are integration smoke samples, not a stabilized performance baseline; some ran alongside build/browser activity. No physical-phone performance is claimed.

- Native generation and verification passed for all three statements with all three backends.
- Browser age generation and verification passed for every backend at 1 and 6 threads, plus one warm-up and 20 full-device verification calls per backend. Exported observations are in `bench/results/browser-comparison/observations.json`.
- Browser registration at 6 threads passed for Chonk DE/US and ProveKit US. ProveKit DE exhausted WASM allocation in `calculate_witness_bounds` at an observed capacity of 3,875,667,968 bytes; the error was retained and the next workload still completed. Independent full-device verification passed for all four cases. See `registration-observations.json` in the same directory.
- Desktop and 390-pixel layouts were inspected; the comparison table scrolls inside the page on narrow screens. Screenshots are alongside those browser observations.
- The two Noir age boundary tests, 17 Groth16 relation/gadget tests, three ProveKit transcript/fresh-process tests and two WASM trap-lifecycle tests passed. ProveKit single-/six-thread and Groth16 six-thread WASM age proofs were also verified natively.
- The complete Node/WASM smoke matrix is in `bench/results/2026-11-16-comparison/`: 18 proving attempts at 1/6 threads, plus all nine warm full-host WASM/native verifier pairs. US registration and age passed with all backends; German registration passed with Chonk but exhausted WASM allocation with Groth16 and ProveKit. Native-generated German proofs still passed both independent verifiers.

## Native comparison

The same prepared fixtures and keys can be measured without WASM:

```sh
# Rebuild only the native executables after source changes.
cargo +stable build --release --manifest-path bench/compare/fixtures/Cargo.toml
node bench/compare/groth16/build.mjs native
node bench/compare/provekit/build.mjs native

cd bench/wasm
node compare.mjs run --runtime native --samples 5 --threads 1,6 --verify-samples 20
npm run build:web
npm run serve
```

Native output goes to `bench/results/<date>-native-comparison/`, separately from the WASM report. The browser links that host report; it does not pretend to execute native code on a phone.

Each sample measures the actual native executable directly with `/usr/bin/time -l`. Witness generation and proof generation are timed together; key/SRS/program preparation is excluded from that timer, but included in the whole-process memory peak. Verification of the generated proof is measured separately, and verification-only sessions warm once before 20 full-host calls. There is no PK-decode timer and no new setup ceremony.

Thread counts are backend worker configurations, not total OS thread counts. Chonk checks its native worker budget; Rust backends report their global Rayon pool size. Upstream native Arkworks MSM can create bounded nested pools. Native Groth16 streams its sparse matrix plan from a buffered file during proving; WASM reads the prepared plan from linear memory. These implementation differences remain part of the comparison.

Recorded native results are in `bench/results/2026-11-16-native-comparison/`. All 18 proving samples passed (three statements × three backends × two worker budgets), as did all nine independent native verifier runs with one warm-up and 20 measured calls. Native and WASM fixture hashes were checked for equality. These are one-sample integration observations, not the five-sample analysis run shown above.

Both complete reports are linked from the running demo: `/reference/report.html` for WASM and `/reference-native/report.html` for native. Their links, labels, nine-row tables, failure/proof-size display and desktop/narrow layouts were checked in Chrome. The subsecond-display regression test also passed; fast native measurements retain useful precision instead of rounding to zero.
