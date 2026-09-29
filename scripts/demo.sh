#!/usr/bin/env bash
# The whole system end to end: builds, starts the devnet node, deploys the pool, and runs Alice
# (US passport) and Bob (DE passport) through identities, bundles, a deposit, a handshake and a
# ratchet transfer, Bob's listener, a split, a merge and a withdrawal, checking the balances.
# The prover's own logging (bb) goes to $DEVNET/prover.log.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
cargo build -q -p emit-devnet-node -p zkpool 2>/dev/null || cargo build -p emit-devnet-node -p zkpool
(cd contracts && forge build >/dev/null 2>&1)
source scripts/devnet.sh
trap 'kill $NODE_PID 2>/dev/null || true' EXIT
BOB_EOA=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC

zk() { "$BIN/zkpool" "$@" 2>>"$DEVNET/prover.log"; }
step() { printf '\n== %s\n' "$*"; }
expect() { grep -F -- "$2" <<<"$1" >/dev/null || { echo "expected '$2' in: $1" >&2; exit 1; }; }

step "identities (each bound to a synthetic passport)"
zk identity new --name alice --document us_rsa4096_rsa2048 | head -3
zk identity new --name bob --document de_bp384_bp256 | head -3

step "bundles exchanged: each accepts the other's"
zk -w alice contact add --name bob --bundle "$(cat "$ZKPOOL_HOME/bob.bundle")"
zk -w bob contact add --name alice --bundle "$(cat "$ZKPOOL_HOME/alice.bundle")"

step "Bob listens (log subscription) while Alice pays"
zk -w bob listen --until 2 --timeout 900 >"$DEVNET/listen.log" &
LISTEN=$!
sleep 2

step "Alice deposits 100, pays Bob 60 (handshake) and 5 (ratchet)"
zk -w alice deposit --amount 100 | tee -a "$DEVNET/tx.log"
zk -w alice transfer --to bob --amount 60 | tee -a "$DEVNET/tx.log"
zk -w alice transfer --to bob --amount 5 | tee -a "$DEVNET/tx.log"
wait "$LISTEN"
cat "$DEVNET/listen.log"
listened=$(cat "$DEVNET/listen.log")
expect "$listened" "received 60 ETH (handshake"
expect "$listened" "received 5 ETH (ratchet index 1"
expect "$listened" "from P<USAERIKSSON<<ANNA<MARIA"

step "Bob syncs from the logs and lists his notes"
zk -w bob sync
zk -w bob notes

step "Bob splits the 60 note (10 + 49.99, fee 0.01), merges the two smallest, withdraws 30"
zk -w bob split --amounts 10,49.99 | tee -a "$DEVNET/tx.log"
zk -w bob merge | tee -a "$DEVNET/tx.log"
zk -w bob withdraw --amount 30 --to "$BOB_EOA" | tee -a "$DEVNET/tx.log"

step "balances"
a=$(zk -w alice balance); b=$(zk -w bob balance)
echo "$a"; echo "$b"
zk -w bob notes
expect "$a" "shielded 34.98 ETH in 1 note(s)"   # 100 - 60 - 5 - 2 fees
expect "$b" "shielded 34.97 ETH in 2 note(s)"   # 65 - 30 - 3 fees
pool=$(cast balance "$ZKPOOL_POOL" --rpc-url "$ZKPOOL_RPC")
[ "$pool" = "69950000000000000000" ] || { echo "pool holds $pool wei" >&2; exit 1; }
echo "pool contract holds 69.95 ETH (= 34.98 + 34.97 shielded)"

step "timings and gas"
sed -E 's/^([a-z]+: [a-z]+ [^:]*): proved in ([0-9.]+ s).*transact gas ([0-9]+).*/\1 | \2 | \3 gas/' "$DEVNET/tx.log" | grep '|'
echo; echo "demo ok"
