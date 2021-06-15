# Tezos zkChannels contract

## Security Warnings

The zkChannels contract is currently under development and has not passed a security audit. It is not suitable for production yet.

## Documentation
Please refer to the [tezos-contract wiki](https://github.com/boltlabs-inc/tezos-contract/wiki) for documentation around the contract.

## zkChannels smart contract

[zkchannels-contract](zkchannels-contract) contains the zkChannels michelson smart contract, as well as the high-level [SmartPy](https://smartpy.io) script used to generate it. The SmartPy script can be compiled and tested using their [online IDE](https://smartpy.io), or by following the instructions in the directory.

## Sandbox testing

[sandbox-tests](sandbox-tests) contains the files and instructions to install the tezos node and test the smart contract using the pytests testing framework.

## Testnet (edo2net) testing

[pytezos-tests](pytezos-tests) contains the files and instructions to run a full lifecycle of a zkChannels contract on testnet using the [pytezos](https://pytezos.baking-bad.org) library.

## License

All code in this workspace is licensed under

 * MIT license ([LICENSE](LICENSE) or http://opensource.org/licenses/MIT)