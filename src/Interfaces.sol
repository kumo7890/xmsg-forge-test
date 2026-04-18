// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IORMPPort {
    function recv(
        uint256 fromChainId,
        address fromDapp,
        address toDapp,
        bytes calldata message
    ) external;

    function ORMP() external view returns (address);
}

interface IMsgportMessager {
    function receiveMessage(
        uint256 fromChainId,
        address fromDapp,
        bytes calldata message
    ) external;

    function remoteMessagerOf(uint256 chainId) external view returns (address);
    function port() external view returns (address);
}

interface IORMP {
    function trusted(address) external view returns (bool);
}