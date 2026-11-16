#!/usr/bin/env bash
# Folds each pipeline once natively and dumps its circuits + inputs for the WASM bench.
# Needs a noir-zk checkout with NOIR_ZK_BENCH_DUMP (NOIR_ZK=path, default ../noir-zk).
set -euo pipefail
cd "$(dirname "$0")/.."
NOIR_ZK=$(cd "${NOIR_ZK:-../noir-zk}" && pwd)
OUT="$PWD/bench/fixtures"
rm -rf "$OUT"
# The path patch rewrites Cargo.lock; put it back.
cp Cargo.lock bench/.Cargo.lock.bak
trap 'mv bench/.Cargo.lock.bak Cargo.lock' EXIT
patch=()
for c in core kernels backend codegen; do
  patch+=(--config "patch.crates-io.noir-zk-$c.path=\"$NOIR_ZK/crates/noir-zk-$c\"")
done
NOIR_ZK_BENCH_DUMP="$OUT" cargo test --release -p zkpool "${patch[@]}" \
  -- --ignored dump_bench_fixtures --nocapture
ls "$OUT"
