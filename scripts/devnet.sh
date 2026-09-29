#!/usr/bin/env bash
# Starts the devnet node and deploys the pool: `source scripts/devnet.sh` exports ZKPOOL_POOL,
# ZKPOOL_HOME and NODE_PID. DEVNET (default .devnet) holds the chain, the logs and the wallets.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DEVNET=${DEVNET:-$ROOT/.devnet}
BIN=${BIN:-$ROOT/target/debug}
RPC=${ZKPOOL_RPC:-http://127.0.0.1:8545}
# The deployer: the standard test mnemonic's account 0 (genesis.json funds it).
DEPLOYER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

if curl -sf -X POST -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' "$RPC" >/dev/null 2>&1; then
  echo "something already serves $RPC: stop it first" >&2
  exit 1
fi
rm -rf "$DEVNET"
mkdir -p "$DEVNET/wallets"
"$BIN/emit-node" node --dev --chain "$ROOT/genesis.json" --datadir "$DEVNET/chain" \
  --http --http.api eth,net,web3,debug,txpool --ws --ws.api eth,net,web3 \
  --disable-discovery --log.file.directory "$DEVNET/logs" >"$DEVNET/node.log" 2>&1 &
NODE_PID=$!
for _ in $(seq 1 120); do
  curl -sf -X POST -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' "$RPC" >/dev/null && break
  kill -0 "$NODE_PID" 2>/dev/null || { cat "$DEVNET/node.log"; exit 1; }
  sleep 0.5
done
grep -E '^(pins|precompiles):' "$DEVNET/node.log" || true

info=$("$BIN/zkpool" info)
export DEPLOYMENT_ROOT=$(awk '/^deployment_root/ {print $2}' <<<"$info")
export PIPELINE_ROOT=$(awk '/^identity_transfer/ {print $2}' <<<"$info")
export REGISTRY_ROOTS="$(awk '/^fixtures_registry/ {print $2}' <<<"$info"),$(awk '/^csca_registry/ {print $2}' <<<"$info")"
(cd "$ROOT/contracts" && forge script script/Deploy.s.sol --rpc-url "$RPC" --broadcast \
  --private-key "$DEPLOYER_KEY" >"$DEVNET/deploy.log" 2>&1) || { cat "$DEVNET/deploy.log"; exit 1; }
export ZKPOOL_POOL=$(awk '/^  EmitV2Pool 0x/ {print $2}' "$DEVNET/deploy.log")
export ZKPOOL_HOME="$DEVNET/wallets"
export NODE_PID
echo "node pid $NODE_PID, rpc $RPC, EmitV2Pool $ZKPOOL_POOL"
