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

    /// The root of the empty tree: zeros(32).
    uint256 public constant EMPTY_ROOT = 0x0b59baa35b9dc267744f0ccb4e3b0255c1fc512460d91130c6bc19fb2668568d;
    /// filled[i]: the last left node at height i.
    uint256[DEPTH] internal filled;
    uint256[ROOT_RING] public roots;
    uint256 public rootIndex;
    uint256 public nextIndex;

    error TreeFull();

    constructor() {
        roots[0] = EMPTY_ROOT;
    }

    /// The root of an empty subtree of height i: zeros(0) = 0, zeros(i + 1) = H(zeros(i), zeros(i)).
    /// Constants (computed with the POSEIDON2 precompile; the wallet's tree test checks the root).
    function zeros(uint256 i) public pure returns (uint256) {
        if (i == 0) return 0;
        if (i == 1) return 0x0b63a53787021a4a962a452c2921b3663aff1ffd8d5510540f8e659e782956f1;
        if (i == 2) return 0x0e34ac2c09f45a503d2908bcb12f1cbae5fa4065759c88d501c097506a8b2290;
        if (i == 3) return 0x21f9172d72fdcdafc312eee05cf5092980dda821da5b760a9fb8dbdf607c8a20;
        if (i == 4) return 0x2373ea368857ec7af97e7b470d705848e2bf93ed7bef142a490f2119bcf82d8e;
        if (i == 5) return 0x120157cfaaa49ce3da30f8b47879114977c24b266d58b0ac18b325d878aafddf;
        if (i == 6) return 0x01c28fe1059ae0237b72334700697bdf465e03df03986fe05200cadeda66bd76;
        if (i == 7) return 0x2d78ed82f93b61ba718b17c2dfe5b52375b4d37cbbed6f1fc98b47614b0cf21b;
        if (i == 8) return 0x067243231eddf4222f3911defbba7705aff06ed45960b27f6f91319196ef97e1;
        if (i == 9) return 0x1849b85f3c693693e732dfc4577217acc18295193bede09ce8b97ad910310972;
        if (i == 10) return 0x2a775ea761d20435b31fa2c33ff07663e24542ffb9e7b293dfce3042eb104686;
        if (i == 11) return 0x0f320b0703439a8114f81593de99cd0b8f3b9bf854601abb5b2ea0e8a3dda4a7;
        if (i == 12) return 0x0d07f6e7a8a0e9199d6d92801fff867002ff5b4808962f9da2ba5ce1bdd26a73;
        if (i == 13) return 0x1c4954081e324939350febc2b918a293ebcdaead01be95ec02fcbe8d2c1635d1;
        if (i == 14) return 0x0197f2171ef99c2d053ee1fb5ff5ab288d56b9b41b4716c9214a4d97facc4c4a;
        if (i == 15) return 0x2b9cdd484c5ba1e4d6efcc3f18734b5ac4c4a0b9102e2aeb48521a661d3feee9;
        if (i == 16) return 0x14f44d672eb357739e42463497f9fdac46623af863eea4d947ca00a497dcdeb3;
        if (i == 17) return 0x071d7627ae3b2eabda8a810227bf04206370ac78dbf6c372380182dbd3711fe3;
        if (i == 18) return 0x2fdc08d9fe075ac58cb8c00f98697861a13b3ab6f9d41a4e768f75e477475bf5;
        if (i == 19) return 0x20165fe405652104dceaeeca92950aa5adc571b8cafe192878cba58ff1be49c5;
        if (i == 20) return 0x1c8c3ca0b3a3d75850fcd4dc7bf1e3445cd0cfff3ca510630fd90b47e8a24755;
        if (i == 21) return 0x1f0c1a8fb16b0d2ac9a146d7ae20d8d179695a92a79ed66fc45d9da4532459b3;
        if (i == 22) return 0x038146ec5a2573e1c30d2fb32c66c8440f426fbd108082df41c7bebd1d521c30;
        if (i == 23) return 0x17d3d12b17fe762de4b835b2180b012e808816a7f2ff69ecb9d65188235d8fd4;
        if (i == 24) return 0x0e1a6b7d63a6e5a9e54e8f391dd4e9d49cdfedcbc87f02cd34d4641d2eb30491;
        if (i == 25) return 0x09244eec34977ff795fc41036996ce974136377f521ac8eb9e04642d204783d2;
        if (i == 26) return 0x1646d6f544ec36df9dc41f778a7ef1690a53c730b501471b6acd202194a7e8e9;
        if (i == 27) return 0x064769603ba3f6c41f664d266ecb9a3a0f6567cd3e48b40f34d4894ee4c361b3;
        if (i == 28) return 0x1595bb3cd19f84619dc2e368175a88d8627a7439eda9397202cdb1167531fd3f;
        if (i == 29) return 0x2a529be462b81ca30265b558763b1498289c9d88277ab14f0838cb1fce4b472c;
        if (i == 30) return 0x0c08da612363088ad0bbc78abd233e8ace4c05a56fdabdd5e5e9b05e428bdaee;
        if (i == 31) return 0x14748d0241710ef47f54b931ac5a58082b1d56b0f0c30d55fb71a6e8c9a6be14;
        revert TreeFull();
    }

    function _insert(uint256 leaf) internal returns (uint256 index) {
        index = nextIndex;
        if (index >= 1 << DEPTH) revert TreeFull();
        uint256 node = leaf;
        uint256 i = index;
        for (uint256 h = 0; h < DEPTH; h++) {
            if (i & 1 == 0) {
                filled[h] = node;
                node = Poseidon2.hash2(node, zeros(h));
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
