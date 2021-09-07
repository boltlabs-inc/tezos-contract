# Pytezos Setup Instructions

This tutorial is designed to walk you through how to test the zkChannels contract on edo2net using [PyTezos](https://github.com/baking-bad/pytezos).

Instructions for Ubuntu 20.04.

Clone tezos-contract repo and navigate to `tezos-contract/pytezos-tests`.
```
    git clone https://github.com/boltlabs-inc/tezos-contract.git
    cd tezos-contract/pytezos-tests
```

Set up python3 virtual environment.
```
    virtualenv --python=python3 venv
    source ./venv/bin/activate
```

We'll need to download [PyTezos](https://github.com/baking-bad/pytezos) to interact with the tezos node. 
```
    sudo apt-get install libsodium-dev libsecp256k1-dev libgmp-dev
    pip3 install -r requirements.txt
```

From the pytezos-tests directory run the `pytezos_contract_tester.py` specifying `--network` , which can be either `"testnet"` or the node RPC uri, e.g.
```
    $ python3 pytezos_contract_tester.py --network=testnet
```
