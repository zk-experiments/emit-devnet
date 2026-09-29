// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Calls to the devnet's POSEIDON2 precompile: Noir's `Poseidon2::hash(inputs, n)` over BN254
/// (the t = 4 sponge the circuits use).
library Poseidon2 {
    function hash(uint256[] memory xs) internal view returns (uint256 h) {
        assembly ("memory-safe") {
            let ok := staticcall(gas(), 0x0101, add(xs, 0x20), mul(mload(xs), 0x20), 0x00, 0x20)
            if iszero(and(ok, eq(returndatasize(), 0x20))) { revert(0, 0) }
            h := mload(0x00)
        }
    }

    function hash2(uint256 a, uint256 b) internal view returns (uint256 h) {
        assembly ("memory-safe") {
            mstore(0x00, a)
            mstore(0x20, b)
            let ok := staticcall(gas(), 0x0101, 0x00, 0x40, 0x00, 0x20)
            if iszero(and(ok, eq(returndatasize(), 0x20))) { revert(0, 0) }
            h := mload(0x00)
        }
    }
}

/// @notice An append-only Merkle tree of depth 32 over Poseidon2 (node = H(left, right), empty leaf 0),
/// with a ring of the last 32 roots, as Emit V1's. The wallet's tree (crates/cli/src/tree.rs) is the same.
abstract contract IMT {
    uint256 public constant DEPTH = 32;
    uint256 public constant ROOT_RING = 32;

    /// zeros[i]: the root of an empty subtree of height i.
    uint256[DEPTH] public zeros;
    /// filled[i]: the last left node at height i.
    uint256[DEPTH] internal filled;
    uint256[ROOT_RING] public roots;
    uint256 public rootIndex;
    uint256 public nextIndex;

    error TreeFull();

    constructor() {
        uint256 z = 0;
        for (uint256 i = 0; i < DEPTH; i++) {
            zeros[i] = z;
            z = Poseidon2.hash2(z, z);
        }
        roots[0] = z;
    }

    function _insert(uint256 leaf) internal returns (uint256 index) {
        index = nextIndex;
        if (index >= 1 << DEPTH) revert TreeFull();
        uint256 node = leaf;
        uint256 i = index;
        for (uint256 h = 0; h < DEPTH; h++) {
            if (i & 1 == 0) {
                filled[h] = node;
                node = Poseidon2.hash2(node, zeros[h]);
            } else {
                node = Poseidon2.hash2(filled[h], node);
            }
            i >>= 1;
        }
        nextIndex = index + 1;
        rootIndex = (rootIndex + 1) % ROOT_RING;
        roots[rootIndex] = node;
    }

    function currentRoot() public view returns (uint256) {
        return roots[rootIndex];
    }

    function isKnownRoot(uint256 root) public view returns (bool) {
        if (root == 0) return false;
        for (uint256 i = 0; i < ROOT_RING; i++) {
            if (roots[i] == root) return true;
        }
        return false;
    }
}
