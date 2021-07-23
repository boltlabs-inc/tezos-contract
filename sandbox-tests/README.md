# Testing with Tezos using BLS12-381
## Building on sandbox

(1a) Build dependencies on Ubuntu 20.04:

    sudo add-apt-repository ppa:avsm/ppa
    sudo apt update
    sudo apt-get install -y rsync git m4 build-essential patch unzip wget pkg-config libgmp-dev libev-dev libhidapi-dev libffi-dev opam=2.0.5-1ubuntu1 jq virtualenv python3-pip 

(1b) Build deps on Mac OS:

    brew install opam libffi gmp libev pkg-config hidapi python3
    pip3 install virtualenv

(2) Install poetry:

    curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python3
    source $HOME/.poetry/env

(3) Install rust 1.44

    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source $HOME/.cargo/env
    rustup toolchain install 1.44.0
    rustup default 1.44.0

To switch back to latest stable version of rust do the following:

    rustup default stable

(4) Clone Tezos here (Edo branch). Make sure you have git 2.18+ installed:

    git clone https://gitlab.com/tezos/tezos.git
    cd tezos
    git checkout v9.0
    opam init --bare -y
    opam switch create for_tezos 4.09.1   (if Linux)
    make build-deps
    eval $(opam env)
    make
    export PATH=~/tezos:$PATH
    source ./src/bin_client/bash-completion.sh
    export TEZOS_CLIENT_UNSAFE_DISABLE_DISCLAIMER=Y

(5) Clone tezos-contract repo

    cd ..
    git clone https://github.com/boltlabs-inc/tezos-contract.git
    cd tezos

(6) Can run pytests (need Python 3.8+)

    virtualenv --python=python3 venv
    source ./venv/bin/activate

(7) Setup poetry environment (using `pyproject.toml` from the sandbox-tests dir)

    cp ../tezos-contract/sandbox-tests/pyproject.toml .
    poetry install 

(8) Run the test sandbox script for the zkChannels contract

    cp -r ../tezos-contract/sandbox-tests/test-files tests_python/
    cp ../tezos-contract/zkchannels-contract/zkchannel_contract.tz tests_python/test-files/
    cd tests_python/
    . test-files/run_test.sh test-files/test_zkchannel.py test-files/out.5f0b6efabc46808589acc4ffcfa9e9c8412cc097e45d523463da557d2c675c67.establish.json test-files/out.5f0b6efabc46808589acc4ffcfa9e9c8412cc097e45d523463da557d2c675c67.close.json 
