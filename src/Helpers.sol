// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SenderCapture {
    address public capturedSender;
    bool    public wasCalled;

    function capture(address resolvedSender) external {
        capturedSender = resolvedSender;
        wasCalled      = true;
    }

    fallback() external {
        wasCalled = true;
    }
}

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
}