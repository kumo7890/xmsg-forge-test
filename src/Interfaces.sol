// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IORMPPort {
    function recv(
        address fromDapp,
        address toDapp,
        bytes calldata message
    ) external payable;

    function ORMP() external view returns (address);
    function ormp() external view returns (address);
    function peerOf(uint256 chainId) external view returns (address);
}

interface IMsgportMessager {
    function receiveMessage(
        uint256 _srcAppChainId,
        address _remoteAppAddress,
        address _localAppAddress,
        bytes memory _message
    ) external;

    function remoteMessagerOf(uint256 chainId) external view returns (address);
    function port() external view returns (address);
}

interface IORMP {
    function trusted(address) external view returns (bool);

    function recv(
        Message calldata message,
        bytes calldata proof
    ) external;
}

struct Message {
    address channel;
    uint256 index;
    uint256 fromChainId;
    address from;
    uint256 toChainId;
    address to;
    uint256 gasLimit;
    bytes encoded;
}

interface IXTokenIssuing {
    function issue(
        uint256 _remoteChainId,
        address _originalToken,
        address _originalSender,
        address _recipient,
        address _rollbackAccount,
        uint256 _amount,
        uint256 _nonce,
        bytes calldata _extData
    ) external;
}