# emit-devnet

The Emit V2 private transfer, end to end on a local chain: a reth dev node whose EVM verifies folded Chonk proofs (`ZK_VERIFY`) and hashes with the circuits' Poseidon2 (`POSEIDON2`), a private note pool contract, and a console wallet (`zkpool`) with which Alice and Bob, each bound to a synthetic passport, deposit, pay each other on the post-quantum channel, split, merge and withdraw. Every transfer is one proof of the `identity_transfer` pipeline: the passport's eid steps, the channel session, DG1 sealed, the 2-in / 2-out JoinSplit, and its note opening sealed, folded with noir-zk's generic kernels.

Design: `emit-v2-transfer-mechanism.md` and `emit-private-transfer-design.md` (the Outbe notes); the circuits and wallet logic come from the `postquantum-zk-encryption-experiment` repository, the channel from [zk-encryption](https://github.com/zk-experiments/zk-encryption), the identity layer from [eid-circuits](https://github.com/zk-experiments/eid-circuits), the pipelines from [noir-zk](https://github.com/zk-experiments/noir-zk).

## Architecture

```
                        pins.toml (versions, catalogs + SHA-256, registry tag + root, deployment root)
                                 │ compiled in, checked at startup (catalogs fetched from the CDNs)
          ┌──────────────────────┴───────────────────────────┐
          ▼                                                  ▼
 crates/cli: zkpool (Alice, Bob)                    crates/node: emit-node (reth v2.6.0, --dev)
 ├ wallet JSON: sk, Receiver, Senders, notes, tree   ├ EVM = Ethereum (Prague) + two precompiles
 ├ Transfer::build → fold(identity_transfer)         │   0x…0100 ZK_VERIFY(pipeline_root ‖ proof)
 │   eid dsc → sod → document → session →            │       → uint256[35] public fields, or revert
 │   DG1 envelope → transfer → note envelope          │   0x…0101 POSEIDON2(x₁..xₙ) → H (Noir's sponge)
 │   → kernel_hiding: one 40,192-byte proof          └ JSON-RPC http :8545, ws :8546
 ├ transact(...) from the user's EOA ───────────────► contracts/: EmitV2Pool (+ IMT, depth 32, 32-root ring)
 └ sync / listen: NewCommitment, NewNullifier,        ├ ZK_VERIFY, then every public field vs calldata,
   Envelope logs → tree, spent notes,                 │   ctx, H(pqCiphertext), roots, nullifiers,
   Receiver::scan → received notes + sender's MRZ     │   registry root, date, scope, msg.value
                                                      └ fee → block.coinbase, vPubOut → payout; events
 crates/circuits: the combining registry
 ├ emit layer (this repo): transfer app frozen as emit-devnet@0.1.0, bytecode bundled
 ├ identity layer: eid-circuits 0.8.0 (eid/dsc, eid/sod, eid/document) wrapped
 ├ channel layer: zk-encryption 0.1.0 (channel/session, envelope, note_envelope) wrapped
 ├ pipelines identity_transfer (7 apps, 32 slots), transfer_only (3 apps) → fold, verify, Outputs, DEPLOYMENT_ROOT
 └ setup: eid DSC/SOD bytecode from the packs on circuits.zk-eid.dev (catalog SHA-256 pinned, pack SHA-256
   from the catalog, every file against eid's registry pins); document steps compiled from eid's source
```

```
crates/circuits/   build.rs (codegen), circuits/manifest.toml (emit family, wrapped families, pipelines),
                   noir/ (transfer app + lib/emit), resources/ + assets/ (frozen key, ABI, bytecode),
                   src/{lib.rs, pins.rs, setup.rs}
crates/node/       src/main.rs (reth CLI + EVM factory), src/precompiles.rs, tests/devnet.rs
crates/cli/        src/{main.rs, wallet.rs, chain.rs, emit.rs, tree.rs, document.rs},
                   fixtures/documents.json (six synthetic passports), tests/cli.rs
contracts/         src/{IMT.sol, EmitV2Pool.sol}, test/EmitV2Pool.t.sol, script/Deploy.s.sol
scripts/           devnet.sh (node + deploy), demo.sh (the whole flow, checked)
genesis.json       chain 3607, Prague from genesis, 300M gas limit, three funded dev accounts
pins.toml
```

## Pins and where each artefact comes from

`pins.toml` is compiled into the node and the wallet and checked at startup (`crates/circuits/src/pins.rs`): the node refuses to start and the wallet refuses to prove if a check fails (`emit-node node --pins-offline` checks only the local ones).

| what | version / pin | from | checked |
|---|---|---|---|
| noir-zk (core, backend, codegen, kernels) | `=0.3.0` | crates.io | kernels family root `0x0eb7f815…937f` and version |
| emit layer (transfer app) | `emit-devnet@0.1.0`, family root `0x12bbf5aa…e702` | this repository (`crates/circuits/noir`, frozen with `noir-zk freeze`, bytecode bundled) | library and family root; bytecode against its pin when loaded |
| channel layer | `zk-encryption@0.1.0`, git rev `8696562` (PR #1, on noir-zk 0.3.0) | bytecode bundled in `zk-encryption-circuits`; catalog `https://circuits.zk-experiments.dev/zk-encryption/0.1.0/catalog.json` | catalog SHA-256 `bbf6cd45…9153`; its families' roots equal the compiled-in ones |
| identity layer | `eid-circuits@0.8.0`, git rev `367b651` (PR #29, on noir-zk 0.3.0) | DSC and SOD steps: packs on `https://circuits.zk-eid.dev`, catalog `catalog@0.7.0.json` (0.8.0's DSC and SOD pins are 0.7.0's, byte for byte; 0.8.0's packs aren't published yet); document steps: compiled from eid's Noir source at the pinned rev with nargo 1.0.0-rc.3 | catalog SHA-256 `39294f2b…53f1` and its 248 DSC/SOD labels in eid's registry; each pack's SHA-256 against the catalog; every unpacked `.b64` / `.vk` and every compiled document step against eid's registry pins |
| CSCA registry | tag `registry-20260928-1039`, root `0x27bef40a…02a2` | `https://registry.zk-eid.dev/<tag>/registry.json` | file SHA-256 `17a21c0f…4444` and `commitment.root` |
| deployment | root `0x2d9395b0…0009`; `identity_transfer` `0x1c9a8489…9624` (7); `transfer_only` `0x2af79540…5da5` (3) | computed by the codegen | equal to the generated constants |
| toolchain | nargo 1.0.0-rc.3, bb 7.0.0-nightly.20260927 (via `barretenberg-rs`), reth v2.6.0, solc 0.8.30 | `~/.toolchains`, crates.io, git tag | nargo path `$NARGO` or `~/.toolchains/noir-1.0.0-rc.3/bin/nargo` |

Caches: `~/.cache/emit-devnet` (`$EMIT_DEVNET_CACHE`): the pinned files, eid's unpacked packs (the demo needs rsa4096, rsa2048, bp384, bp256: about 235 MB) and eid's source checkout with the compiled document steps. The prover reads bb's CRS from `~/.bb-crs` (`$BB_CRS_PATH`), checked against noir-zk's pinned hashes.

## Running it

Prerequisites: Rust 1.94+, Foundry (forge, cast), nargo 1.0.0-rc.3 at `~/.toolchains/noir-1.0.0-rc.3/bin/nargo` (or `$NARGO`), bb's CRS in `~/.bb-crs`, network access the first time.

```sh
git submodule update --init          # forge-std
scripts/demo.sh                      # builds, starts the node, deploys, runs Alice and Bob, checks balances
cargo test -- --ignored devnet       # the same as a test, against a spawned node (ports 28545-28551, 30545)
cargo test                           # unit tests: pins, pipelines, precompiles, the tree's root, the CLI offline
(cd contracts && forge test)         # the pool's logic with a mocked verifier and hash
```

By hand: `source scripts/devnet.sh` starts the node (`.devnet/`) and deploys the pool, exporting `ZKPOOL_POOL`, `ZKPOOL_HOME`, `ZKPOOL_RPC`, `ZKPOOL_WS`; then:

```sh
zkpool identity new --name alice --document us_rsa4096_rsa2048
zkpool identity new --name bob --document de_bp384_bp256
zkpool -w alice contact add --name bob --bundle "$(cat $ZKPOOL_HOME/bob.bundle)"
zkpool -w bob listen &                       # Ctrl-C to stop, or --until N / --timeout S
zkpool -w alice deposit --amount 100
zkpool -w alice transfer --to bob --amount 60   # the handshake
zkpool -w alice transfer --to bob --amount 5    # the ratchet
zkpool -w bob notes
zkpool -w bob split --amounts 10,49.99
zkpool -w bob merge
zkpool -w bob withdraw --amount 30 --to 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
zkpool -w bob balance
```

The node alone: `emit-node node --dev --chain genesis.json --http --ws` (all of reth's flags apply). The pool: `scripts/devnet.sh` runs `forge script script/Deploy.s.sol` with `DEPLOYMENT_ROOT`, `PIPELINE_ROOT` and `REGISTRY_ROOTS` from `zkpool info`; the deployer's first contract is `0x5FbDB2315678afecb367f032d93F642f64180aa3`.

Dev accounts (the standard test mnemonic, funded with 10⁹ ETH in `genesis.json`; never use them elsewhere):

| role | address | private key |
|---|---|---|
| deployer (pool owner) | `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` | `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80` |
| Alice | `0x70997970C51812dc3A010C7d01b50e0d17dc79C8` | `0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d` |
| Bob | `0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC` | `0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a` |

## The precompiles

`ZK_VERIFY` at `0x0000000000000000000000000000000000000100`: input `pipeline_root (32 bytes) ‖ proof` (a whole number of 32-byte fields). The pipeline must be one of the pinned deployment's (`identity_transfer`, `transfer_only`); the proof is verified under noir-zk's hiding key with the deployment root, the pipeline root and length checked, and the output is every public field ABI-encoded as `uint256[]`: `deployment_root, pipeline_root, length`, then the pipeline's slots in order (35 fields for `identity_transfer`). A proof that doesn't verify reverts with the reason as bytes, after charging the gas. Gas: `1,200,000 + 3 per 32-byte word`: verification takes 17-20 ms on an Apple M5 Max (the wallet times it before each send), priced at ecrecover's rate (3,000 gas for about 50 µs, 60 Mgas/s); with the 40,224-byte input that is 1,203,771.

`POSEIDON2` at `0x0000000000000000000000000000000000000101`: input `n ≥ 1` 32-byte big-endian field elements, each below the BN254 scalar modulus (otherwise it halts); returns Noir's `Poseidon2::hash(inputs, n)` (t = 4, rate 3, the same `pso-poseidon` code the circuits' Rust mirror uses). Gas: `60 + 360 per permutation`, one permutation per three inputs (a tree node: 420; the ciphertext commitment, 53 inputs: 6,540).

## The contracts

`EmitV2Pool` (inherits `IMT`), constructor `(bytes32 deploymentRoot, bytes32 pipelineRoot)`:

- `transact(bytes32 root, bytes32[2] nullifiers, bytes32[2] commitments, uint256 vPubIn, uint256 vPubOut, uint256 fee, address payout, bytes pqCiphertext, bytes proof) payable`: calls `ZK_VERIFY`; compares the public fields with the calldata by the pipeline's slot order (`cid = block.chainid`, root, N₀, N₁, C₀, C₁, vPubIn, vPubOut, fee, payout) and the deployment and pipeline roots; recomputes `ctx = H("emit-v2/ctx", cid, N₀, N₁, C₀, C₁)`; checks `ct = H("eid-envelope/latticect/v1", u ‖ v)` over the 1,536-byte ML-KEM ciphertext exactly as zk-encryption's `Ciphertext::commitment` packs it (ByteDecode₁₂, every coefficient < q, 20 coefficients per field, the first lowest); the root is in the ring of the last 32; the nullifiers are unspent and distinct; the registry root is accepted; `|date − block.timestamp| ≤ 1 day`; `scope = 0`; `msg.value = vPubIn`. Then marks both nullifiers spent, inserts both commitments, emits `NewNullifier(bytes32)` ×2, `NewCommitment(bytes32 commitment, uint256 leafIndex)` ×2 and `Envelope(bytes32 cT, bytes32[2] e, bytes32 tag, bytes32 ct, bytes pqCiphertext, bytes32[6] cNote, bytes32[6] cId)`, pays `fee` to `block.coinbase` and `vPubOut` to `payout`.
- Owner: `addRegistryRoot(uint256)` (a ring of 8), `setDateTolerance(uint256)`, `transferOwnership(address)`.
- Views: `currentRoot()`, `isKnownRoot(uint256)`, `roots(uint256)`, `nextIndex()`, `zeros(uint256)`, `EMPTY_ROOT`, `nullifierSpent(uint256)`, `isKnownRegistryRoot(uint256)`, `registryRoots(uint256)`, `ctCommitment(bytes)`, `deploymentRoot()`, `pipelineRoot()`, `owner()`.
- Errors: `InvalidProof(bytes)`, `OutputMismatch(string field)`, `BadCiphertext`, `UnknownRoot`, `NullifierSpent`, `UnknownRegistryRoot`, `DateOutOfRange`, `NonZeroScope`, `ValueMismatch`, `PaymentFailed`, `NotOwner`, `TreeFull`.

`IMT`: an append-only depth-32 tree over `POSEIDON2` (node `H(left, right)`, empty leaf 0, the empty subtrees' roots as constants), filled-subtree inserts, a ring of the last 32 roots. The wallet's tree (`crates/cli/src/tree.rs`) is the same, and a test checks the empty root.

## The wallet

`zkpool [--home DIR] [--rpc URL] [--ws URL] [--pool ADDR] [-w NAME] [--chain-id 3607] <command>` (each also from `ZKPOOL_*`); amounts in ETH.

| command | what it does |
|---|---|
| `info [--check]` | the deployment and pipeline roots, the fixtures' registry root and the published one, the pin checks (`--check` fetches the catalogs and registry) |
| `identity new --name N --document D [--key K]` | binds a fixture passport, generates the shielded key `sk` (`pk = H("emit-v2/pk", sk)`) and the receiver's keys (Grumpkin + ML-KEM-768), writes the wallet and prints the bundle (base64url, also `<home>/<N>.bundle`); alice and bob get their dev EOAs |
| `identity show` | the bundle again |
| `contact add --name N --bundle B` | accepts a bundle (format, chain id, validity window, Grumpkin key on the curve, ML-KEM key and its commitment): the handshake's prerequisite |
| `deposit --amount A [--fee F]` | vPubIn = A from the EOA, dummy inputs, a note of A − F to itself, on a throwaway channel |
| `transfer --to N --amount A [--fee 0.01]` | spends one or two notes: A to the contact's `pk`, the change to itself; the first transfer to a contact is the handshake, later ones ratchet; the channel state is written before broadcasting |
| `withdraw --amount A --to ADDR [--fee 0.01]` | vPubOut = A to ADDR, the change to itself |
| `split --amounts a[,b] [--fee 0.01]` | one note into two: `a,b` needs a note worth exactly a + b + fee, `a` alone keeps the rest in the second |
| `merge [--fee 0.01]` | the two smallest notes into one |
| `notes`, `balance` | the notes (leaf, value, commitment, sender's MRZ), the shielded and EOA balances |
| `sync` | catches up from the pool's logs: the tree, spent notes, the pending outputs, and every Envelope through `Receiver::scan` |
| `listen [--until N] [--timeout S]` | subscribes to the pool's logs over WebSocket and syncs on each, printing received notes with the sender's MRZ |

Each transaction is proven in-process: eid-prover v0.8.0 selects the passport's DSC, SOD and document steps and builds their inputs (fresh salts, today's date, scope 0), the channel envelope seals DG1 under the transfer's chain key, and `identity_transfer::fold` folds the seven apps; the wallet then verifies the proof locally (as `ZK_VERIFY` will) and sends `transact` from its EOA. The fee leaves the shielded value to the block producer.

## Measured (Apple M5 Max, 18 cores; `scripts/demo.sh`, one run)

| transaction | passport | prove | gas |
|---|---|---:|---:|
| Alice deposits 100 | US: RSA-4096 → RSA-2048 | 2.46 s | 3,323,475 |
| Alice → Bob 60 (handshake) | US | 2.47 s | 2,775,044 |
| Alice → Bob 5 (ratchet) | US | 2.47 s | 2,779,474 |
| Bob splits 60 → 10 + 49.99 | DE: brainpoolP384 → brainpoolP256 | 4.64 s | 2,780,478 |
| Bob merges 5 + 10 → 14.99 | DE | 4.65 s | 2,787,682 |
| Bob withdraws 30 | DE | 4.65 s | 2,797,175 |

Every proof is 40,192 bytes (calldata 42,148 bytes) and verifies in 17-20 ms. A transfer's 2.78M gas: 564k calldata (EIP-7623's floor, 1.38M, isn't binding), 1.20M `ZK_VERIFY`, 34k for 66 `POSEIDON2` calls (64 tree nodes, ctx, the ciphertext commitment), about 545k decoding and packing the ML-KEM ciphertext in Solidity, and the rest storage (nullifiers, tree, root ring), the Envelope event and the payments. The first deposit pays about 550k more for the tree's first writes. The whole demo takes about 40 s with the packs cached (first run: about 235 MB of packs and two document steps compiled).

## What is devnet-only

- **Sending from the user's EOA.** The design sends `transact` from a one-time address with a zero gas price, the fee paid only from the shielded value; that needs a zero-fee path (a sequencer or mempool rule admitting such transactions when the proof checks out) that this dev chain doesn't have. Here each user's funded EOA sends and pays gas, which links their transactions to their account; the protocol fee still goes from the shielded value to `block.coinbase`. (reth's dev mode rotates the coinbase per block, so the fees land on throwaway addresses.)
- **Registry roots set by the owner.** The pool accepts the csca-registry roots its owner adds (the deploy adds the fixtures' root and the pinned published one); a real chain would have an eid module following the registry.
- **Synthetic passports.** The six fixtures (US, DE, FR, IT, NL, ES) are mock documents signed by mock CSCAs; the pool accepts their registry's root. Two users may even share a passport.
- **eid v0.8.0 is a draft.** Its DSC and SOD bytecode comes from v0.7.0's packs (same pins) and its document steps are compiled from source, until v0.8.0's packs are published; zk-encryption is consumed from its PR branch on noir-zk 0.3.0.
- **Dev keys and chain.** Well-known keys, chain id 3607, instant blocks, one node; the datadir is thrown away by `scripts/devnet.sh`.

## Gaps

- The pool accepts only `identity_transfer` proofs; `transfer_only` is declared, pinned and verifiable by `ZK_VERIFY`, but its slot layout (no registry root, date or scope) would need a second slot map in the contract.
- No minimum note value or fixed fee schedule (the design's open point); fees are whatever the wallet passes.
- The ciphertext commitment is packed in Solidity (about 545k gas); assembly or a precompile would cut most of it.
- `ZK_VERIFY` runs twice per block (building and validating) and isn't cached; the gas constant is from one machine.
- The wallet keeps the whole tree and recomputes paths in O(n) per spend; fine for a devnet.
- A failed ratchet transaction leaves its chain index consumed (the receiver's window of 8 absorbs it); a failed handshake restarts the contact's channel.
- The Foundry tests mock both precompiles; the real hash and verifier are exercised by the devnet test and the demo.
