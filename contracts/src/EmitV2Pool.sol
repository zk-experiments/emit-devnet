// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IMT, Poseidon2} from "./IMT.sol";

/// @notice The Emit V2 private note pool: one entry point, `transact`, for deposits, private transfers and
/// withdrawals, each a folded proof of the `identity_transfer` pipeline (a passport's eid steps, the channel
/// session, DG1 sealed, the 2-in / 2-out JoinSplit, its note opening sealed) verified by the ZK_VERIFY
/// precompile. The checks are the design's "What the chain checks" (emit-v2-transfer-mechanism.md §5).
contract EmitV2Pool is IMT {
    address internal constant ZK_VERIFY = address(0x0100);

    /// Poseidon2 domains (the ASCII tag as a big-endian integer).
    uint256 internal constant D_CTX = 0x656d69742d76322f637478; // "emit-v2/ctx"
    uint256 internal constant D_LATTICE_CT = 0x6569642d656e76656c6f70652f6c61747469636563742f7631; // "eid-envelope/latticect/v1"

    /// The ML-KEM-768 ciphertext (u, v) as ByteEncode_12: 1024 coefficients mod q.
    uint256 public constant PQ_CIPHERTEXT_BYTES = 1536;
    uint256 internal constant Q = 3329;

    /// The public fields of an identity_transfer proof: deployment root, pipeline root, length, then the
    /// pipeline's 32 slots (circuits/manifest.toml; `Outputs::from_fields` in the generated code).
    uint256 internal constant F_DEPLOYMENT = 0;
    uint256 internal constant F_PIPELINE = 1;
    uint256 internal constant F_REGISTRY_ROOT = 3;
    uint256 internal constant F_DATE = 4;
    uint256 internal constant F_SCOPE = 5;
    uint256 internal constant F_CTX = 7;
    uint256 internal constant F_C_T = 8;
    uint256 internal constant F_E_X = 9;
    uint256 internal constant F_E_Y = 10;
    uint256 internal constant F_TAG = 11;
    uint256 internal constant F_CT = 12;
    uint256 internal constant F_C_ID = 13; // 13..18
    uint256 internal constant F_CID = 19;
    uint256 internal constant F_ROOT = 20;
    uint256 internal constant F_N0 = 21;
    uint256 internal constant F_C0 = 23;
    uint256 internal constant F_V_IN = 25;
    uint256 internal constant F_V_OUT = 26;
    uint256 internal constant F_FEE = 27;
    uint256 internal constant F_PAYOUT = 28;
    uint256 internal constant F_C_NOTE = 29; // 29..34
    uint256 internal constant FIELDS = 35;

    uint256 public constant REGISTRY_RING = 8;

    bytes32 public immutable deploymentRoot;
    bytes32 public immutable pipelineRoot;
    address public owner;
    uint256 public dateTolerance = 1 days;
    uint256[REGISTRY_RING] public registryRoots;
    uint256 public registryIndex;
    mapping(uint256 => bool) public nullifierSpent;

    event NewNullifier(bytes32 nullifier);
    event NewCommitment(bytes32 commitment, uint256 leafIndex);
    event Envelope(
        bytes32 cT, bytes32[2] e, bytes32 tag, bytes32 ct, bytes pqCiphertext, bytes32[6] cNote, bytes32[6] cId
    );
    event RegistryRoot(uint256 root);

    error NotOwner();
    error InvalidProof(bytes reason);
    error OutputMismatch(string field);
    error BadCiphertext();
    error UnknownRoot();
    error NullifierSpent();
    error UnknownRegistryRoot();
    error DateOutOfRange();
    error NonZeroScope();
    error ValueMismatch();
    error PaymentFailed();

    constructor(bytes32 deploymentRoot_, bytes32 pipelineRoot_) {
        deploymentRoot = deploymentRoot_;
        pipelineRoot = pipelineRoot_;
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @notice Accepts a csca-registry root (a ring of the last REGISTRY_RING). Devnet: the owner sets them;
    /// on a real chain an eid module holds them.
    function addRegistryRoot(uint256 root) external onlyOwner {
        registryIndex = (registryIndex + 1) % REGISTRY_RING;
        registryRoots[registryIndex] = root;
        emit RegistryRoot(root);
    }

    function setDateTolerance(uint256 seconds_) external onlyOwner {
        dateTolerance = seconds_;
    }

    function transferOwnership(address to) external onlyOwner {
        owner = to;
    }

    function isKnownRegistryRoot(uint256 root) public view returns (bool) {
        if (root == 0) return false;
        for (uint256 i = 0; i < REGISTRY_RING; i++) {
            if (registryRoots[i] == root) return true;
        }
        return false;
    }

    /// @notice Spends two notes (nullifiers) and creates two (commitments). A deposit has vPubIn = msg.value
    /// and dummy inputs; a withdrawal pays vPubOut to `payout`; the fee goes to the block producer.
    function transact(
        bytes32 root,
        bytes32[2] calldata nullifiers,
        bytes32[2] calldata commitments,
        uint256 vPubIn,
        uint256 vPubOut,
        uint256 fee,
        address payout,
        bytes calldata pqCiphertext,
        bytes calldata proof
    ) external payable {
        uint256[] memory f = _verify(proof);

        // The proof's public fields are the calldata's.
        _eq(f[F_CID], block.chainid, "cid");
        _eq(f[F_ROOT], uint256(root), "root");
        _eq(f[F_N0], uint256(nullifiers[0]), "n0");
        _eq(f[F_N0 + 1], uint256(nullifiers[1]), "n1");
        _eq(f[F_C0], uint256(commitments[0]), "c0");
        _eq(f[F_C0 + 1], uint256(commitments[1]), "c1");
        _eq(f[F_V_IN], vPubIn, "vPubIn");
        _eq(f[F_V_OUT], vPubOut, "vPubOut");
        _eq(f[F_FEE], fee, "fee");
        _eq(f[F_PAYOUT], uint256(uint160(payout)), "payout");
        // ctx isn't calldata: recomputed from the transfer's own fields.
        _eq(f[F_CTX], _ctx(nullifiers, commitments), "ctx");
        // ct = H(pqCiphertext), as the session app commits it.
        _eq(f[F_CT], _ctCommitment(pqCiphertext), "ct");

        // The pool's state and the document.
        if (!isKnownRoot(uint256(root))) revert UnknownRoot();
        if (
            nullifiers[0] == nullifiers[1] || nullifierSpent[uint256(nullifiers[0])]
                || nullifierSpent[uint256(nullifiers[1])]
        ) revert NullifierSpent();
        if (!isKnownRegistryRoot(f[F_REGISTRY_ROOT])) revert UnknownRegistryRoot();
        uint256 date = f[F_DATE];
        if (date + dateTolerance < block.timestamp || date > block.timestamp + dateTolerance) {
            revert DateOutOfRange();
        }
        if (f[F_SCOPE] != 0) revert NonZeroScope();
        if (msg.value != vPubIn) revert ValueMismatch();

        // Effects.
        for (uint256 i = 0; i < 2; i++) {
            nullifierSpent[uint256(nullifiers[i])] = true;
            emit NewNullifier(nullifiers[i]);
        }
        for (uint256 i = 0; i < 2; i++) {
            emit NewCommitment(commitments[i], _insert(uint256(commitments[i])));
        }
        _envelope(f, pqCiphertext);

        // Value leaving the pool: the fee to the block producer, vPubOut to the payout account.
        _pay(block.coinbase, fee);
        _pay(payout, vPubOut);
    }

    function _verify(bytes calldata proof) internal view returns (uint256[] memory f) {
        (bool ok, bytes memory ret) = ZK_VERIFY.staticcall(abi.encodePacked(pipelineRoot, proof));
        if (!ok) revert InvalidProof(ret);
        f = abi.decode(ret, (uint256[]));
        if (f.length != FIELDS) revert InvalidProof("fields");
        _eq(f[F_DEPLOYMENT], uint256(deploymentRoot), "deployment root");
        _eq(f[F_PIPELINE], uint256(pipelineRoot), "pipeline root");
    }

    function _envelope(uint256[] memory f, bytes calldata pqCiphertext) internal {
        bytes32[6] memory cNote;
        bytes32[6] memory cId;
        for (uint256 i = 0; i < 6; i++) {
            cNote[i] = bytes32(f[F_C_NOTE + i]);
            cId[i] = bytes32(f[F_C_ID + i]);
        }
        emit Envelope(
            bytes32(f[F_C_T]),
            [bytes32(f[F_E_X]), bytes32(f[F_E_Y])],
            bytes32(f[F_TAG]),
            bytes32(f[F_CT]),
            pqCiphertext,
            cNote,
            cId
        );
    }

    function _pay(address to, uint256 amount) internal {
        if (amount == 0) return;
        (bool ok,) = payable(to).call{value: amount}("");
        if (!ok) revert PaymentFailed();
    }

    function _eq(uint256 got, uint256 want, string memory field) internal pure {
        if (got != want) revert OutputMismatch(field);
    }

    /// H("emit-v2/ctx", cid, N0, N1, C0, C1).
    function _ctx(bytes32[2] calldata n, bytes32[2] calldata c) internal view returns (uint256) {
        uint256[] memory xs = new uint256[](6);
        xs[0] = D_CTX;
        xs[1] = block.chainid;
        xs[2] = uint256(n[0]);
        xs[3] = uint256(n[1]);
        xs[4] = uint256(c[0]);
        xs[5] = uint256(c[1]);
        return Poseidon2.hash(xs);
    }

    /// Poseidon2("eid-envelope/latticect/v1", u ‖ v as canonical 12-bit coefficients, 20 per field, the
    /// first coefficient lowest): zk-encryption's `Ciphertext::commitment`. The bytes are ByteDecode_12'd and
    /// every coefficient must be < q.
    function ctCommitment(bytes calldata ct) external view returns (uint256) {
        return _ctCommitment(ct);
    }

    function _ctCommitment(bytes calldata ct) internal view returns (uint256) {
        if (ct.length != PQ_CIPHERTEXT_BYTES) revert BadCiphertext();
        uint256[] memory xs = new uint256[](53);
        xs[0] = D_LATTICE_CT;
        // 1024 coefficients, two per three bytes; field k holds coefficients 20k .. 20k + 19.
        for (uint256 j = 0; j < 512; j++) {
            uint256 b0 = uint8(ct[3 * j]);
            uint256 b1 = uint8(ct[3 * j + 1]);
            uint256 b2 = uint8(ct[3 * j + 2]);
            uint256 c0 = b0 | ((b1 & 0x0f) << 8);
            uint256 c1 = (b1 >> 4) | (b2 << 4);
            if (c0 >= Q || c1 >= Q) revert BadCiphertext();
            uint256 i = 2 * j;
            xs[1 + i / 20] |= c0 << (12 * (i % 20));
            xs[1 + (i + 1) / 20] |= c1 << (12 * ((i + 1) % 20));
        }
        return Poseidon2.hash(xs);
    }
}
