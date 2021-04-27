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
    pip3 install pytezos
```

You should be able to run `zkchannel_edo2net_broadcaster.py` using the files in the `sample_files` folder as follows. The arguments `--cust` and `--merch` specify testnet accounts that can be used on edo2net. `--custclose` and `--merchclose` correspond to json files that the customer and merchant would receive respectively from libzkchannels when a channel closure is initiated. 
```
    $ python3 zkchannel_edo2net_broadcaster.py --contract=../zkchannels-contract/zkchannel_contract.tz --cust=sample_files/tz1S6eSPZVQzHyPF2bRKhSKZhDZZSikB3e51.json --merch=sample_files/tz1VcYZwxQoyxfjhpNiRkdCUe5rzs53LMev6.json --custclose=sample_files/cust_close.json --merchclose=sample_files/merch_close.json 
```
