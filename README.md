# xmsg-forge-test

## Introduction
`xmsg-forge-test` is a Foundry test suite for a smart contract security Proof of Concept (PoC). This project demonstrates and validates critical vulnerabilities in smart contracts, focusing on cross-chain message forgery and sender validation.

## Purpose
The purpose of this repository is to:
- Simulate and test common vulnerabilities in cross-chain communication.
- Provide a secure PoC implementation using Foundry's testing framework.
- Evaluate mitigation techniques, including ERC-2771 compliance.

## Repository Structure
```
xmsg-forge-test/
├── foundry.toml                   # Foundry configuration file
├── src/
│   ├── Interfaces.sol             # Interface definitions for the PoC
│   └── Helpers.sol                # Support contracts for sender extraction and reporting
├── test/
│   └── XmsgSenderForgeTest.t.sol  # Unit, fuzz, and fork tests
└── .github/
    └── workflows/
        └── forge-test.yml         # GitHub Actions workflow for CI
```

## Installation & Setup
To get started, clone the repository and run the following commands to install dependencies:

```bash
git clone https://github.com/kumo7890/xmsg-forge-test.git
cd xmsg-forge-test

# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Install dependencies
forge install
```

## Running Tests
The repository includes unit tests, fuzz tests, and fork tests:

### Unit Tests
```bash
forge test --match-test "testUnit" -vvvv
```

### Fuzz Tests
```bash
forge test --match-test "testFuzz" -vvvv
```

### Fork Tests
To run fork tests, set your Ethereum RPC URL as an environment variable and execute:
```bash
export ETH_RPC_URL="https://your-alchemy-or-infura-endpoint"
forge test --fork-url $ETH_RPC_URL --match-test "testForge" -vvvv
```

## GitHub Actions
A CI workflow is included in `.github/workflows/forge-test.yml`. The following steps are automatically tested:
1. Unit tests
2. Validation of ORMP relay on-chain
3. Fork tests for message forging scenarios

## Contributing
Contributions are welcome! If you'd like to contribute:
1. Fork the repository.
2. Create a new branch for your changes.
3. Submit a pull request providing details of your updates.

Ensure new code has test cases and adheres to the code style.

## License
This repository is licensed under the MIT License. See [LICENSE](./LICENSE) for details.

## Acknowledgments
Thanks to the Foundry team and open-source contributors for providing tools and examples for secure smart contract development and testing.