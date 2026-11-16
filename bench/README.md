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
