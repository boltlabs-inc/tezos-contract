#!/bin/bash

# Build script to compile/test the smart contract using the SmartPy CLI. 
# Includes an optional argument to specify a target directory to copy 
# the generated contract file. Default target is the current directory.
#
# Usage: ./build-contract.sh [ /optional/path/to/dir ]
#

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

function fail() {
  printf "${RED}[!] $1${NC}\n"
  exit 1
}

function console() {
  printf "${GREEN}[+] $1${NC}\n"
}

OS_TYPE=$(uname)
OS_RELEASE=/etc/os-release

function get_os_release_id() {
  if [[ -f "$OS_RELEASE" ]] ; then
    awk -F= '$1=="ID" { print $2 ;}' $OS_RELEASE
  elif [[ $OS_TYPE == "Darwin"* ]] ; then
    echo 'darwin'
  else
    echo 'unknown'
  fi
}

function get_os_release_version() {
  if [[ -f $OS_RELEASE ]] ; then
    awk -F= '$1=="VERSION" { print $2 ;}' $OS_RELEASE
  elif [[ $OS_TYPE == "darwin"* ]] ; then
    uname -s | tr '[:upper:]' '[:lower:]'
  else
    echo 'unknown'
  fi
}

function brew_install() {
    console "Installing $1"
    if brew list $1 &>/dev/null; then
        echo "${1} is already installed"
    else
        brew install $1 && echo "$1 is installed"
    fi
}

function smartpy_install() {
  console "Installing SmartPy -> $1"
  INSTALL=$1/SmartPy.sh
  if test -f "$INSTALL"; then
    echo "Found SmartPy.sh script installed"
  else
    # install the smartPy CLI v0.7.4 (if not currently present)
    sh <(curl -s https://smartpy.io/releases/20210904-98c3fb1314a5298a5000fe3801d0b57238469670/cli/install.sh) local-install $1
  fi
}

# early termination if any of the commands fail
set -e

OS_RELEASE_ID=$(get_os_release_id)
OS_RELEASE_VERSION=$(get_os_release_version)

TEMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'tmp-dir')
SMARTPY_DIR=tmp-smartpy-cli
CONTRACT_TARGET_DIR=${1:-.}
SMARTPY_CONTRACT=zkchannels-contract/zkchannel_smartpy_script.py
COMMIT_HASH=$(git rev-parse --short HEAD)

if [ ! -d "$CONTRACT_TARGET_DIR" ]; then
  fail "'$CONTRACT_TARGET_DIR' directory does not exist! Please try again."
fi
# get the full path to contract target dir
CONTRACT_TARGET_DIR=$(realpath -s $CONTRACT_TARGET_DIR)

if ! [[ "$OS_RELEASE_ID" =~ ^(darwin|debian|ubuntu|fedora|centos)$ ]] ; then
  fail "Need install steps for $OS_RELEASE_ID"
fi

# check and install system dependencies first
if [[ "$OS_RELEASE_ID" = 'darwin' ]] ; then
    console "Detected MacOS ($OS_TYPE)"
    brew_install coreutils
elif [[ "$OS_RELEASE_ID" = 'ubuntu' ]] ; then
    console "Detected Ubuntu ($OS_VERSION)"
elif [[ "$OS_RELEASE_ID" = 'debian' ]] ; then
    console "Detected Debian ($OS_VERSION)"
else
    console "Detected ${OS_RELEASE_ID} ($OS_VERSION)"
fi
# attempt smartpy install in the current dir
smartpy_install ${SMARTPY_DIR}

console "Compiling & testing smart contract..."
set -x
# create the output dir
mkdir -p $TEMP_DIR/
# test the script to ensure no build errors
$SMARTPY_DIR/SmartPy.sh test $SMARTPY_CONTRACT $TEMP_DIR/
# then proceed to compile the smartPy script in the target output directory
$SMARTPY_DIR/SmartPy.sh compile $SMARTPY_CONTRACT $TEMP_DIR/
set +x

console "Installing the compiled contract..."
set -x
# identify the contract using the latest HEAD & clean up
cp ${TEMP_DIR}/compiled_contract/*_contract.tz ${CONTRACT_TARGET_DIR}/zkchannel_contract_${COMMIT_HASH}.tz
cp ${TEMP_DIR}/compiled_contract/*_contract.json ${CONTRACT_TARGET_DIR}/zkchannel_contract_${COMMIT_HASH}.json
rm -rf $TEMP_DIR

set +x