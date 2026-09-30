# emit-devnet

The Emit V2 private transfer, end to end on a local chain: a reth dev node whose EVM verifies folded Chonk proofs (`ZK_VERIFY`) and hashes with the circuits' Poseidon2 (`POSEIDON2`), a private note pool contract, and a console wallet (`zkpool`) with which Alice and Bob, each bound to a synthetic passport, deposit, pay each other on the post-quantum channel, split, merge and withdraw. Every transfer is one proof folded with noir-zk's generic kernels: of the `identity_transfer` pipeline (the passport's eid steps, the channel session, DG1 sealed, the 2-in / 2-out JoinSplit, and its note opening sealed) or, once the holder has registered in the pool's identity cache (the passport proved once, `identity_register`), of `member_transfer` (membership in the identity tree instead of the passport, the JoinSplit bound to the registered key; see [The identity cache](#the-identity-cache)).

Design: `emit-v2-transfer-mechanism.md` and `emit-private-transfer-design.md` (the Outbe notes); the circuits and wallet logic come from the `postquantum-zk-encryption-experiment` repository, the channel from [zk-encryption](https://github.com/zk-experiments/zk-encryption), the identity layer from [eid-circuits](https://github.com/zk-experiments/eid-circuits), the pipelines from [noir-zk](https://github.com/zk-experiments/noir-zk).

## Architecture

```
                        pins.toml (versions, catalogs + SHA-256, registry tag + root, deployment root)
                                 │ compiled in, checked at startup (catalogs fetched from the CDNs)
          ┌──────────────────────┴───────────────────────────┐
          ▼                                                  ▼
 crates/cli: zkpool (Alice, Bob)                    crates/node: emit-node (reth v2.6.0, --dev)
 ├ wallet JSON: sk, Receiver, Senders, notes, tree,  ├ EVM = Ethereum (Prague) + two precompiles
 │   registration, identity tree                     │   0x…0100 ZK_VERIFY(pipeline_root ‖ proof)
 ├ identity register → fold(identity_register)       │       → uint256[35] public fields, or revert
 │   eid dsc → sod → document → register              │   0x…0101 POSEIDON2(x₁..xₙ) → H (Noir's sponge)
 ├ Transfer::build → fold(member_transfer)           └ JSON-RPC http :8545, ws :8546
 │   identity_member → session → DG1 envelope →
 │   transfer_holder → note envelope
 │   (no live registration or --full-passport:
 │   fold(identity_transfer): eid dsc → sod →
 │   document → session → DG1 envelope → transfer →
 │   note envelope) → one 40,192-byte proof
 ├ register / transact from the user's EOA ─────────► contracts/: EmitV2Pool (+ IMT, depth 32, 32-root ring;
 └ sync / listen: NewCommitment, NewNullifier,        │   IdentityTree, the same, for registrations)
   Envelope, IdentityRegistered logs → trees,         ├ ZK_VERIFY, then every public field vs calldata,
   spent notes, registration,                         │   ctx, H(pqCiphertext), roots, nullifiers,
   Receiver::scan → received notes + sender's MRZ     │   registry or identity root, date, scope, msg.value
                                                      └ fee → block.coinbase, vPubOut → payout; events
 crates/circuits: the combining registry
 ├ this repo's layers, frozen as emit-devnet@0.2.0, bytecode bundled: emit (transfer, transfer_holder),
 │   identity_cache (register, member)
 ├ identity layer: eid-circuits 0.8.0 (eid/dsc, eid/sod, eid/document) wrapped
 ├ channel layer: zk-encryption 0.1.0 (channel/session, envelope, note_envelope) wrapped
 ├ pipelines identity_transfer (7 apps, 32 slots), transfer_only (3 apps), identity_register (4 apps, 6 slots),
 │   member_transfer (5 apps, 31 slots) → fold, verify, Outputs, DEPLOYMENT_ROOT
 └ setup: eid DSC/SOD/document bytecode from the packs on circuits.zk-eid.dev (catalog SHA-256 pinned,
   pack SHA-256 from the catalog, every file against eid's registry pins)
```

```
crates/circuits/   build.rs (codegen), circuits/manifest.toml (own and wrapped families, pipelines),
                   noir/ (apps transfer, transfer_holder, register, identity_member; lib/emit,
                   lib/identity_cache), resources/ + assets/ (frozen keys, ABIs, bytecode),
                   src/{lib.rs, pins.rs, setup.rs}
crates/node/       src/main.rs (reth CLI + EVM factory), src/precompiles.rs, tests/devnet.rs
crates/cli/        src/{main.rs, wallet.rs, chain.rs, emit.rs, identity.rs, tree.rs, document.rs},
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
| this repository's layers (emit: transfer, transfer_holder; identity_cache: register, member) | `emit-devnet@0.2.0`, family roots `transfer` `0x101453d9…c2b6`, `transfer_holder` `0x09d917b9…0106`, `register` `0x15c06b7f…2247`, `member` `0x180deeff…ce09` | this repository (`crates/circuits/noir`, frozen with `noir-zk freeze`, bytecode bundled) | library and every family root; bytecode against its pin when loaded |
| channel layer | `zk-encryption@0.1.0`, git rev `8696562` (main since PR #1, on noir-zk 0.3.0 from crates.io) | bytecode bundled in `zk-encryption-circuits`; catalog `https://circuits.zk-experiments.dev/zk-encryption/0.1.0/catalog.json` | catalog SHA-256 `bbf6cd45…9153`; its families' roots equal the compiled-in ones |
| identity layer | `eid-circuits@0.8.0`, git tag `v0.8.0` (`eid-circuits`, `eid-prover`) | DSC, SOD and document steps: packs on `https://circuits.zk-eid.dev`, catalog `catalog@0.8.0.json` | catalog SHA-256 `f9119063…e092`, its version and its DSC/SOD/document labels in eid's registry; each pack's SHA-256 against the catalog; every unpacked `.b64` / `.vk` against eid's registry pins |
| CSCA registry | tag `registry-20260928-1039`, root `0x27bef40a…02a2` | `https://registry.zk-eid.dev/<tag>/registry.json` | file SHA-256 `17a21c0f…4444` and `commitment.root` |
| deployment | root `0x04f06ffb…bdb9`; `identity_transfer` `0x2e18854a…968b` (7); `transfer_only` `0x1cd91016…14d4` (3); `identity_register` `0x22c0bc71…1066` (4); `member_transfer` `0x26af3817…26cb` (5) | computed by the codegen | equal to the generated constants |
| toolchain | nargo 1.0.0-rc.3, bb 7.0.0-nightly.20260927 (via `barretenberg-rs`), reth v2.6.0, solc 0.8.30 | `~/.toolchains`, crates.io, git tag | nargo and noir-zk-cli 0.3.0 only to refreeze this repo's layers: `nargo compile --workspace` in `crates/circuits/noir`, then `noir-zk freeze --target noir/target --out . --assets assets` in `crates/circuits` (`~/.toolchains/noir-1.0.0-rc.3/bin/nargo`, `~/.toolchains/noir-zk-0.3.0/bin/noir-zk`) |

Caches: `~/.cache/emit-devnet` (`$EMIT_DEVNET_CACHE`): the pinned files, eid's unpacked packs (the demo needs common, rsa4096, rsa2048, bp384, bp256: about 300 MB). The prover reads bb's CRS from `~/.bb-crs` (`$BB_CRS_PATH`), checked against noir-zk's pinned hashes.

## Running it

Prerequisites: Rust 1.94+, Foundry (forge, cast), bb's CRS in `~/.bb-crs`, network access the first time.

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
zkpool -w alice identity register              # the passport proved once (optional: without it, every
zkpool -w bob identity register                #   transaction proves the passport, identity_transfer)
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

The node alone: `emit-node node --dev --chain genesis.json --http --ws` (all of reth's flags apply). The pool: `scripts/devnet.sh` runs `forge script script/Deploy.s.sol` with `DEPLOYMENT_ROOT`, `TRANSFER_PIPELINE`, `REGISTER_PIPELINE`, `MEMBER_PIPELINE` and `REGISTRY_ROOTS` from `zkpool info`; the deployer's first contract is `0x5FbDB2315678afecb367f032d93F642f64180aa3`.

Dev accounts (the standard test mnemonic, funded with 10⁹ ETH in `genesis.json`; never use them elsewhere):

| role | address | private key |
|---|---|---|
| deployer (pool owner) | `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` | `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80` |
| Alice | `0x70997970C51812dc3A010C7d01b50e0d17dc79C8` | `0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d` |
| Bob | `0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC` | `0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a` |

## The precompiles

`ZK_VERIFY` at `0x0000000000000000000000000000000000000100`: input `pipeline_root (32 bytes) ‖ proof` (a whole number of 32-byte fields). The pipeline must be one of the pinned deployment's (`identity_transfer`, `transfer_only`, `identity_register`, `member_transfer`); the proof is verified under noir-zk's hiding key with the deployment root, the pipeline root and length checked, and the output is every public field ABI-encoded as `uint256[]`: `deployment_root, pipeline_root, length`, then the 32 slots, the pipeline's in order and zeros after (always 35 fields). A proof that doesn't verify reverts with the reason as bytes, after charging the gas. Gas: `1,200,000 + 3 per 32-byte word`: verification takes 17-20 ms on an Apple M5 Max (the wallet times it before each send), priced at ecrecover's rate (3,000 gas for about 50 µs, 60 Mgas/s); with the 40,224-byte input that is 1,203,771.

`POSEIDON2` at `0x0000000000000000000000000000000000000101`: input `n ≥ 1` 32-byte big-endian field elements, each below the BN254 scalar modulus (otherwise it halts); returns Noir's `Poseidon2::hash(inputs, n)` (t = 4, rate 3, the same `pso-poseidon` code the circuits' Rust mirror uses). Gas: `60 + 360 per permutation`, one permutation per three inputs (a tree node: 420; the ciphertext commitment, 53 inputs: 6,540).

## The contracts

`EmitV2Pool` (inherits `IMT`), constructor `(bytes32 deploymentRoot, bytes32 transferPipeline, bytes32 registerPipeline, bytes32 memberPipeline)` (the roots of `identity_transfer`, `identity_register`, `member_transfer`); it deploys its `IdentityTree` (an `IMT` only the pool appends to).

- `register(bytes proof)`: calls `ZK_VERIFY` with `registerPipeline`; the registry root is accepted; `|date − block.timestamp| ≤ 1 day`; `scope = registrationScope(date / IDENTITY_EPOCH)`; the document's nullifier (in that scope) is unused, then marked used; `date ≤ expiry < (epoch + 1) · IDENTITY_EPOCH`. Appends the leaf to the identity tree and emits `IdentityRegistered(bytes32 leaf, uint256 index, uint256 expiry)`.
- `transact(bytes32 pipeline, bytes32 root, bytes32[2] nullifiers, bytes32[2] commitments, uint256 vPubIn, uint256 vPubOut, uint256 fee, address payout, bytes pqCiphertext, bytes proof) payable`: `pipeline` is `transferPipeline` (then the registry root is accepted and `scope = 0`) or `memberPipeline` (then the identity root is in the identity tree's ring of 32), anything else reverts `UnknownPipeline`; calls `ZK_VERIFY`; compares the public fields with the calldata by the pipeline's slot order (the transfer's fields start at slot 4 for `identity_transfer`, 3 for `member_transfer`) (`cid = block.chainid`, root, N₀, N₁, C₀, C₁, vPubIn, vPubOut, fee, payout) and the deployment and pipeline roots; recomputes `ctx = H("emit-v2/ctx", cid, N₀, N₁, C₀, C₁)`; checks `ct = H("eid-envelope/latticect/v1", u ‖ v)` over the 1,536-byte ML-KEM ciphertext exactly as zk-encryption's `Ciphertext::commitment` packs it (ByteDecode₁₂, every coefficient < q, 20 coefficients per field, the first lowest); the root is in the ring of the last 32; the nullifiers are unspent and distinct; `|date − block.timestamp| ≤ 1 day`; `msg.value = vPubIn`. Then marks both nullifiers spent, inserts both commitments, emits `NewNullifier(bytes32)` ×2, `NewCommitment(bytes32 commitment, uint256 leafIndex)` ×2 and `Envelope(bytes32 cT, bytes32[2] e, bytes32 tag, bytes32 ct, bytes pqCiphertext, bytes32[6] cNote, bytes32[6] cId)`, pays `fee` to `block.coinbase` and `vPubOut` to `payout`.
- Owner: `addRegistryRoot(uint256)` (a ring of 8), `setDateTolerance(uint256)`, `transferOwnership(address)`.
- Views: `currentRoot()`, `isKnownRoot(uint256)`, `roots(uint256)`, `nextIndex()`, `zeros(uint256)`, `EMPTY_ROOT`, `nullifierSpent(uint256)`, `isKnownRegistryRoot(uint256)`, `registryRoots(uint256)`, `ctCommitment(bytes)`, `deploymentRoot()`, `transferPipeline()`, `registerPipeline()`, `memberPipeline()`, `identities()` (the `IdentityTree`: `currentRoot()`, `isKnownRoot(uint256)`, `nextIndex()`, …), `registrationScope(uint256 epoch)`, `IDENTITY_EPOCH` (7 days), `documentRegistered(uint256)`, `owner()`.
- Errors: `InvalidProof(bytes)`, `OutputMismatch(string field)`, `UnknownPipeline`, `BadCiphertext`, `UnknownRoot`, `UnknownIdentityRoot`, `NullifierSpent`, `UnknownRegistryRoot`, `DateOutOfRange`, `NonZeroScope`, `WrongScope`, `AlreadyRegistered`, `ExpiryOutOfRange`, `ValueMismatch`, `PaymentFailed`, `NotOwner`, `TreeFull` (`IdentityTree`: `NotPool`).

`IMT`: an append-only depth-32 tree over `POSEIDON2` (node `H(left, right)`, empty leaf 0, the empty subtrees' roots as constants), filled-subtree inserts, a ring of the last 32 roots. The wallet's tree (`crates/cli/src/tree.rs`) is the same, and a test checks the empty root.

## The wallet

`zkpool [--home DIR] [--rpc URL] [--ws URL] [--pool ADDR] [-w NAME] [--chain-id 3607] [--full-passport] <command>` (each also from `ZKPOOL_*`); amounts in ETH. With a live registration every transaction proves `member_transfer`; `--full-passport` forces `identity_transfer`.

| command | what it does |
|---|---|
| `info [--check]` | the deployment and pipeline roots, the fixtures' registry root and the published one, the pin checks (`--check` fetches the catalogs and registry) |
| `identity new --name N --document D [--key K]` | binds a fixture passport, generates the shielded key `sk` (`pk = H("emit-v2/pk", sk)`) and the receiver's keys (Grumpkin + ML-KEM-768), writes the wallet and prints the bundle (base64url, also `<home>/<N>.bundle`); alice and bob get their dev EOAs |
| `identity show` | the bundle again |
| `identity register [--force]` | proves `identity_register` once (the document in this epoch's registration scope, read from the pool) and sends `register`; keeps the leaf, its index, the DG1 salt and the expiry (the epoch's last second or the passport's expiry, whichever is first) in the wallet |
| `contact add --name N --bundle B` | accepts a bundle (format, chain id, validity window, Grumpkin key on the curve, ML-KEM key and its commitment): the handshake's prerequisite |
| `deposit --amount A [--fee F]` | vPubIn = A from the EOA, dummy inputs, a note of A − F to itself, on a throwaway channel |
| `transfer --to N --amount A [--fee 0.01]` | spends one or two notes: A to the contact's `pk`, the change to itself; the first transfer to a contact is the handshake, later ones ratchet; the channel state is written before broadcasting |
| `withdraw --amount A --to ADDR [--fee 0.01]` | vPubOut = A to ADDR, the change to itself |
| `split --amounts a[,b] [--fee 0.01]` | one note into two: `a,b` needs a note worth exactly a + b + fee, `a` alone keeps the rest in the second |
| `merge [--fee 0.01]` | the two smallest notes into one |
| `notes`, `balance` | the notes (leaf, value, commitment, sender's MRZ), the shielded and EOA balances |
| `sync` | catches up from the pool's logs: the note tree, spent notes, the pending outputs, the identity tree (`IdentityRegistered`, which also gives the wallet's own leaf its index), and every Envelope through `Receiver::scan` |
| `listen [--until N] [--timeout S]` | subscribes to the pool's logs over WebSocket and syncs on each, printing received notes with the sender's MRZ |

Each transaction is proven in-process. With a live registration: identity_member proves the wallet's leaf under the identity tree's current root at today's date and commits DG1 afresh, the channel envelope seals it under the transfer's chain key, and `member_transfer::fold` folds the five apps. Otherwise eid-prover v0.8.0 selects the passport's DSC, SOD and document steps and builds their inputs (fresh salts, today's date, scope 0), and `identity_transfer::fold` folds the seven apps. The wallet then verifies the proof locally (as `ZK_VERIFY` will) and sends `transact` from its EOA. The fee leaves the shielded value to the block producer. Dummy inputs (deposits, splits) are held by the wallet's own key with fresh nullifiers, as `transfer_holder` requires.

## Measured (Apple M5 Max, 18 cores; `scripts/demo.sh`, one run)

| transaction | passport | pipeline | prove | gas |
|---|---|---|---:|---:|
| Alice registers | US: RSA-4096 → RSA-2048 | `identity_register` | 1.82 s | 2,591,865 |
| Bob registers | DE: brainpoolP384 → brainpoolP256 | `identity_register` | 3.88 s | 2,007,314 |
| Alice deposits 100 | US | `member_transfer` | 1.37 s | 3,331,703 |
| Alice → Bob 60 (handshake) | US | `member_transfer` | 1.35 s | 2,783,318 |
| Alice → Bob 5 (ratchet) | US | `identity_transfer` (`--full-passport`) | 2.37 s | 2,781,979 |
| Bob splits 60 → 10 + 49.99 | DE | `member_transfer` | 1.36 s | 2,788,870 |
| Bob merges 5 + 10 → 14.99 | DE | `member_transfer` | 1.36 s | 2,796,244 |
| Bob withdraws 30 | DE | `member_transfer` | 1.36 s | 2,805,075 |

For comparison, the previous run with every transaction on `identity_transfer`: 2.46-2.47 s (US) and 4.64-4.65 s (DE), 2,775,044-2,797,175 gas (3,323,475 for the first deposit). A member transfer proves in about 1.36 s whatever the passport: 45 % less than the US passport's full proof, 71 % less than the DE one's. The floor is the rest of the fold: the ML-KEM session app (53,381 gates) and the kernels (one step kernel per app, each verifying two folded proofs). Its gas is the full transfer's plus about 1,500 (the identity root looked up in `IdentityTree`'s ring instead of the registry ring); the proof and calldata are the same size. A registration costs a proof verification (1.2M), its calldata (40,260 B) and one identity-tree insert (the first one writes the tree's filled subtrees: 2.59M, later ones about 2.0M).

Every proof is 40,192 bytes and verifies in 16-18 ms. A transfer's 2.78M gas: 564k calldata (EIP-7623's floor, 1.38M, isn't binding), 1.20M `ZK_VERIFY`, 34k for 66 `POSEIDON2` calls (64 tree nodes, ctx, the ciphertext commitment), about 545k decoding and packing the ML-KEM ciphertext in Solidity, and the rest storage (nullifiers, tree, root ring), the Envelope event and the payments. The first deposit pays about 550k more for the tree's first writes. The whole demo takes about 30 s with the packs cached (first run: about 300 MB of packs).

## The identity cache

Proving the passport on every transfer costs eid's DSC, SOD and document steps each time (about 1 s for an RSA passport, 3.3 s for the German brainpool one on top of the transfer), even for a split or a merge to oneself; the chain can't exempt self-transfers because the receiver is hidden. The identity cache pays for the passport once per registration: later transfers prove membership in an on-chain identity tree instead, and the receiver still gets the sender's MRZ through the DG1 envelope, as before.

**Circuits** (this repository, `emit-devnet@0.2.0`; `crates/circuits/noir/lib/identity_cache`, `lib/emit`):

| app | family (layout) | record | gates |
|---|---|---|---:|
| `register` | `identity_cache/register`: link in 0 (`PayloadCommitment`), public `leaf`, `expiry` | `[payload_commitment, leaf, expiry]` | 4,201 |
| `identity_member` | `identity_cache/member`: link out 0 (`PayloadCommitment`), public `identity_root`, `date`, `holder_tag` | `[payload_commitment, identity_root, date, holder_tag]` | 4,728 |
| `transfer_holder` | `emit/transfer_holder`: binds `ctx` (0) and `holder_tag` (1), link out 12, public from 2 as `transfer` | `[ctx, holder_tag, cid, root, N₀, N₁, C₀, C₁, v_in, v_out, fee, payout, note_commitment]` | 6,766 (`transfer`: 6,738) |

- `register(payload_salt, dg1, sk, expiry)` parses the DG1 bytes with eid's own `parse_dg1` (eid-circuits v0.8.0's `eid_steps`), rebuilds the payload with eid's `plaintext` and recomputes `commit(payload_salt, payload)`, which the kernel checks equals the document step's link; asserts `expiry ≤` the passport's date of expiry (the MRZ's, last second, UTC); publishes the leaf `L = H(IDENTITY, H(PK, sk), H(payload), expiry)` (`IDENTITY = "emit-v2/identity"`; the holder's shielded address, the six-field DG1 payload hashed, the expiry) and `expiry`.
- `identity_member(identity_root, date, sk, payload, payload_salt, expiry, index, path, ctx)` recomputes the leaf, checks its depth-32 path to `identity_root` and `date ≤ expiry`, and returns a fresh `commit(payload_salt, payload)` as its link (the DG1 envelope continues it unchanged) and the holder tag `H(HOLDER, sk, ctx)` (`HOLDER = "emit-v2/holder"`).
- `transfer_holder` is `transfer` with `ins[0].sk = ins[1].sk` (dummies included) and `holder_tag = H(HOLDER, ins[0].sk, ctx)` in its record; the kernel binds it to the member's published tag, and `ctx` to the session's.

**Pipelines** (the deployment has four; every one within 32 slots):

| pipeline | positions | apps / folded circuits | slots |
|---|---|---|---:|
| `identity_transfer` | eid/dsc, eid/sod, eid/document, channel/session, channel/envelope, emit/transfer, channel/note_envelope | 7 / 15 | 32 |
| `transfer_only` | channel/session, emit/transfer, channel/note_envelope | 3 / 7 | 22 |
| `identity_register` | eid/dsc, eid/sod, eid/document, identity_cache/register | 4 / 9 | 6: registry_root, date, scope, nullifier, leaf, expiry |
| `member_transfer` | identity_cache/member, channel/session, channel/envelope, emit/transfer_holder, channel/note_envelope | 5 / 11 | 31: identity_root, date, holder_tag, then the session's, the envelope's, the transfer's and the note envelope's |

(Folded circuits: the apps, a kernel per app, and the hiding kernel.)

**Design decisions and deviations from the brief:**

- *How register knows the passport's expiry.* It re-derives it from the MRZ: the private input is the 95-byte DG1 buffer rather than the six payload fields, from which the circuit rebuilds the payload (so the commitment check against the document's link pins the bytes: `pack_be` is injective) and reads the date of expiry exactly as the document step does. Capping at `date + window` with `date` bound to the document's slot would not be sound: a passport expiring tomorrow could register past it. The cost is small (the register app is 4,201 gates in all). The window cap is the chain's: `expiry` must fall in the registration date's epoch.
- *Holder binding and the order of the apps.* The ordering problem dissolves: `identity_member` takes `ctx` as a private input rather than binding the session's slot, and `transfer_holder` binds `holder_tag` to the member's published slot and `ctx` to the session's. Equal tags mean equal `(sk, ctx)` (Poseidon2's collision resistance), so the member's `sk` is the spender's and its `ctx` the transfer's, and membership can come first, as the brief's pipeline has it. The wallet knows ctx before proving anything (it is computed from the nullifiers and commitments). `ctx` is unique per transfer, so the tag links nothing.
- *Which input's key.* `transfer_holder` requires both inputs held by one key and tags that key; the wallet makes its dummy inputs with its own key (fresh `rho`, so fresh nullifiers). A transfer can't spend a note of another key alongside the holder's.
- *The transfer v2 is a new circuit, not a new version of `transfer`:* a version bump deprecates the old one, and `identity_transfer` keeps `transfer@1.0.0` (bytecode, key and family unchanged; only the library's version, hence its family root, moved to 0.2.0).
- *Scope.* Registration does not use `scope = 0`: the document step's scope must be `registrationScope(epoch)`, `keccak256("emit-v2/register", chainid, pool, epoch) mod p` with `epoch = date / 7 days`, and the contract records the document's nullifier in that scope. One scope for the pool's lifetime would allow one registration per passport ever, so it rotates per epoch, and a registration can't outlive its epoch (`expiry < (epoch + 1) · 7 days`): a passport has at most one live registration per pool at any time. `identity_transfer` keeps `scope = 0`.
- *Contracts.* The identity tree is a second contract (`IdentityTree is IMT`, created by the pool), not a second tree inside the pool: `IMT` keeps its state in contract storage. `transact` gained a leading `bytes32 pipeline` argument. The chain checks the date against the block time for both transfer pipelines; the registration's expiry is checked against that date in the circuit.

**Soundness notes:**

- *Revocation.* A registration is checked against the CSCA registry once, when it is made; revoking the DSC or CSCA afterwards takes effect only when the registration expires, at the end of its epoch (at most 7 days, plus the 1-day date tolerance, as a member proof's date may lag the block by a day). `IDENTITY_EPOCH` should therefore match the registry's revocation latency. Likewise the passport's own expiry: a registration made on its last day ends with it.
- *Privacy.* A registration is public (its leaf, expiry, document nullifier in the epoch's scope, and here the EOA that sent it), but later transfers don't reveal which leaf they prove: a member proof publishes only the identity root, the date and a holder tag that changes with every ctx. The anonymity set is the tree's leaves at that root; which root of the ring a proof uses dates it roughly. The document nullifier is unlinkable across epochs and pools and is not the full pipeline's (scope 0 gives 0).
- *A leaked `sk`* lets its holder spend the notes and prove membership as the registered identity (the MRZ goes to receivers under that name) until the registration expires: the same as losing the notes, and no worse than today, where `identity_transfer` doesn't bind the spender's key to the passport at all (anyone with a passport can spend notes whose key they know).
- *One passport, many holder keys:* prevented within an epoch by the scoped nullifier (implemented, above). Two users sharing a passport (the devnet's fixtures allow it) can't both register in the same epoch.
- *Front-running.* A register proof commits to its leaf; anyone may submit it, with the same effect.

## What is devnet-only

- **Sending from the user's EOA.** The design sends `transact` from a one-time address with a zero gas price, the fee paid only from the shielded value; that needs a zero-fee path (a sequencer or mempool rule admitting such transactions when the proof checks out) that this dev chain doesn't have. Here each user's funded EOA sends and pays gas, which links their transactions to their account; the protocol fee still goes from the shielded value to `block.coinbase`. (reth's dev mode rotates the coinbase per block, so the fees land on throwaway addresses.)
- **Registry roots set by the owner.** The pool accepts the csca-registry roots its owner adds (the deploy adds the fixtures' root and the pinned published one); a real chain would have an eid module following the registry.
- **Synthetic passports.** The six fixtures (US, DE, FR, IT, NL, ES) are mock documents signed by mock CSCAs; the pool accepts their registry's root. Two users may even share a passport.
- **zk-encryption by revision.** The channel layer is consumed at git rev `8696562` (v0.1.0's circuits on noir-zk 0.3.0), not yet at a release tag.
- **Dev keys and chain.** Well-known keys, chain id 3607, instant blocks, one node; the datadir is thrown away by `scripts/devnet.sh`.

## Gaps

- The pool accepts `identity_transfer` and `member_transfer` transfers and `identity_register` registrations; `transfer_only` is declared, pinned and verifiable by `ZK_VERIFY` but accepted by no entry point.
- `identity_transfer` doesn't bind the spender's key to the passport (only `member_transfer` does, through the holder tag): a full-passport transfer proves someone holds a valid passport, not that the notes' owner does.
- A registration can't be revoked early (no per-leaf revocation list); the epoch bounds it. An epoch that ends right after registering leaves a short registration (the wallet then falls back to the full passport until it registers again in the next epoch; `identity register --force`).
- The wallet keeps the whole identity tree, like the note tree, and uses the latest root; the ring keeps 32 roots, so a proof made while 32 other registrations land is refused (resync and prove again).
- The holder-binding test (`cargo test --release -- --ignored holder`) proves; the CI-style `cargo test` doesn't.
- No minimum note value or fixed fee schedule (the design's open point); fees are whatever the wallet passes.
- The ciphertext commitment is packed in Solidity (about 545k gas); assembly or a precompile would cut most of it.
- `ZK_VERIFY` runs twice per block (building and validating) and isn't cached; the gas constant is from one machine.
- The wallet keeps the whole tree and recomputes paths in O(n) per spend; fine for a devnet.
- A failed ratchet transaction leaves its chain index consumed (the receiver's window of 8 absorbs it); a failed handshake restarts the contact's channel.
- The Foundry tests mock both precompiles; the real hash and verifier are exercised by the devnet test and the demo.
