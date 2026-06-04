// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Deployed as toDapp — captures what _xmsgSender() resolves to
/// by mirroring the exact assembly pattern used in the vulnerable contracts
contract SenderCapture {
    address public capturedSender;
    bool    public wasCalled;

    function capture(address resolvedSender) external {
        capturedSender = resolvedSender;
        wasCalled      = true;
    }

    // Mirrors _xmsgSender() assembly exactly
    // When called by ORMPPort.recv(), reads last 20 bytes of calldata
    fallback() external {
        wasCalled = true;
        address extracted;
        assembly {
            extracted := shr(96, calldataload(sub(calldatasize(), 20)))
        }
        capturedSender = extracted;
    }

    receive() external payable {}
}

/// @notice Standalone reporter — call directly to verify
/// what any given calldata tail resolves to
contract SenderReporter {
    function extractSender() external pure returns (address extracted) {
        require(msg.data.length >= 4 + 20, "calldata too short");
        assembly {
            extracted := shr(96, calldataload(sub(calldatasize(), 20)))
        }
    }

    function extractSenderVerbose()
        external
        pure
        returns (address extracted, uint256 calldataLen)
    {
        require(msg.data.length >= 4 + 20, "calldata too short");
        calldataLen = msg.data.length;
        assembly {
            extracted := shr(96, calldataload(sub(calldatasize(), 20)))
        }
    }

    /// @notice Simulate exactly what _xmsgSender() reads
    /// given a full calldata blob — use in tests to pre-verify alignment
    function simulateXmsgSender(
        bytes calldata data
    ) external pure returns (address extracted) {
        require(data.length >= 20, "data too short");
        bytes memory d = data;
        assembly {
            let ptr := add(d, mload(d))
            extracted := shr(96, mload(ptr))
        }
    }