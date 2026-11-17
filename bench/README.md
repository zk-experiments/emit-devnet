# Circuit benchmarks (WASM)

Proving time, memory, verify time, proof and circuit size of each proving pipeline, with bb in
WASM (bb.js) and ACVM in WASM (acvm_js), as a stand-in for on-device proving (iPhone 17).

```sh
# 1. Fold each pipeline natively once and dump its circuits + inputs (needs a noir-zk checkout
#    with NOIR_ZK_BENCH_DUMP; NOIR_ZK=path, default ../noir-zk).
./bench/fixtures.sh
# 2. Run (Node >= 22, macOS for /usr/bin/time -l).
cd bench/wasm && npm install && node bench.mjs run --samples 5 --threads 1,6
```

Results: `bench/results/<date>/{report.md,timings.csv,metadata.json}`.

## Matched registration and age comparison

See [`compare/README.md`](compare/README.md) for the local cross-implementation experiment:
the PR's exact German BP384/BP256 and US RSA4096/RSA2048 registration relations,
plus a shared age-verification circuit instead of member/payment operations.
It compares Chonk, Arkworks Groth16 and ProveKit WHIR, with the same summary layout,
1/6-thread WASM samples, process footprint, and warm full-host WASM/native verification.

The existing Chonk runner and historical PR results above are preserved.
The new entry points are `node bench/compare/fixtures.mjs`,
`node bench/compare/prepare.mjs`, and `cd bench/wasm && npm run compare`.
The browser demo is built with `npm run build:web` and served with `npm run serve`.
Use `npm run compare -- --runtime native` for the same fixtures on native executables.
Native and WASM host reports are stored separately and linked separately from the demo.
