// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {EmitV2Pool} from "../src/EmitV2Pool.sol";

/// Deploys the pool for the pinned deployment and accepts the given csca-registry roots.
/// Env: DEPLOYMENT_ROOT, PIPELINE_ROOT (pins.toml; `zkpool info` prints them), REGISTRY_ROOTS
/// (comma-separated: the synthetic fixtures' root and the published registry's).
contract Deploy is Script {
    function run() external returns (EmitV2Pool pool) {
        bytes32 deployment = vm.envBytes32("DEPLOYMENT_ROOT");
        bytes32 pipeline = vm.envBytes32("PIPELINE_ROOT");
        uint256[] memory registries = vm.envUint("REGISTRY_ROOTS", ",");
        vm.startBroadcast();
        pool = new EmitV2Pool(deployment, pipeline);
        for (uint256 i = 0; i < registries.length; i++) {
            pool.addRegistryRoot(registries[i]);
        }
        vm.stopBroadcast();
        console.log("EmitV2Pool", address(pool));
    }
}
