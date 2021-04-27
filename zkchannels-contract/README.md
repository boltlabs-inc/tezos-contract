# Compiling and testing zkchannels smartpy contract

The zkchannels smart contract [zkchannel_contract.tz](zkchannel_contract.tz) is created by compiling a script written in a SmartPy. The high level script is contained in [zkchannel_smartpy_script](zkchannel_smartpy_script.py), along with unit tests for each entrypoint.

## Installing SmartPy

SmartPy needed to run compile and test the SmartPy script. Alternatively, you can also use the [SmartPy online IDE](https://smartpy.io) by copying and pasting [zkchannel_smartpy_script](zkchannel_smartpy_script.py) into the editor.

For full instructions on installing SmartPy, visit [https://gitlab.com/SmartPy/smartpy](https://gitlab.com/SmartPy/smartpy).

Instructions for building on Ubuntu 20.04:

Clone tezos-contract repo.
```
    git clone https://github.com/boltlabs-inc/tezos-contract.git
```

Install rust for Tezos submodule (requires rust compiler 1.44.0).
```
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    rustup toolchain install 1.44.0
    rustup override set 1.44.0
```

Clone the SmartPy repo
```
    git clone --recurse-submodules https://gitlab.com/SmartPy/SmartPy
```

Install dependencies via [Nix](https://nixos.org/download.html).
```
    curl -L https://nixos.org/nix/install | sh
    env/nix/init
```

We can enter the adapted environment by either running a new shell.
```
    ./envsh
```

To build for the first time run:
```
    ./with_env make full
```

Otherwise to build afterwards run:
```
    ./with_env make
```

Create a new directory to store the output, and run unit tests for zkChannels contract as follows::
```
    mkdir tmp
    smartpy-cli/SmartPy.sh test ../tezos-contract/zkchannels-contract/zkchannel_smartpy_script.py tmp/
```

