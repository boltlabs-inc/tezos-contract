#!/bin/bash

# Build script to compile/test the smart contract using the SmartPy CLI. 
# Includes an optional argument to specify a target directory to copy 
# the generated contract file. Default target dir is the current directory.
#
# Usage: ./build-contract.sh [ /optional/path/to/dir ]
#

CENTOS_RELEASE=/etc/centos-release
REDHAT_RELEASE=/etc/redhat-release
FEDORA_RELEASE=/etc/fedora-release
LSB_RELEASE=/etc/lsb-release
ORACLE_RELEASE=/etc/oracle-release
SYSTEM_RELEASE=/etc/system-release
DEBIAN_VERSION=/etc/debian_version

PURPLE='\033[0;95m'
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

function platform() {
  local  __out=$1
  if [[ -f "$LSB_RELEASE" ]] && grep -q 'DISTRIB_ID=Ubuntu' $LSB_RELEASE; then
    FAMILY="debian"
    eval $__out="ubuntu"
  elif [[ -f "$DEBIAN_VERSION" ]]; then
    FAMILY="debian"
    eval $__out="debian"
  elif [[ -f "$FEDORA_RELEASE" ]]; then
    FAMILY="fedora"
    eval $__out="fedora"
  elif [[ -f "$CENTOS_RELEASE" ]]; then
    FAMILY="centos"
    eval $__out="centos"
  elif [[ -f "$REDHAT_RELEASE" ]]; then
    FAMILY="redhat"
    eval $__out="redhat"
  else
    eval $__out=`uname -s | tr '[:upper:]' '[:lower:]'`
  fi
}

function distro() {
  local __out=$2
  if [[ $1 = "ubuntu" ]]; then
    eval $__out=`awk -F= '/DISTRIB_CODENAME/ { print $2 }' $LSB_RELEASE`
  elif [[ $1 = "darwin" ]]; then
    eval $__out=`sw_vers -productVersion | awk -F '.' '{print $1 "." $2}'`
  elif [[ $1 = "debian" ]]; then
    eval $__out="`cat /etc/os-release | grep 'VERSION=' | cut -c 9-`"
  else
    eval $__out="unknown_version"
  fi
}

OUTPUT_DIR=tmp-contract
CONTRACT_TARGET_DIR=${1:-.}
SMARTPY_CONTRACT=zkchannels-contract/zkchannel_smartpy_script.py
COMMIT_HASH=$(git rev-parse --short HEAD)

if [ ! -d "$CONTRACT_TARGET_DIR" ]; then
  fail "'$CONTRACT_TARGET_DIR' directory does not exist! Please try again."
fi
# get the full path to contract target dir
CONTRACT_TARGET_DIR=$(realpath -s $CONTRACT_TARGET_DIR)

if [[ "$(uname)" = "Darwin" ]]; then
    console "Compiling on MacOS ($(uname))"
else
  platform OS
  distro $OS OS_VERSION

  if [[ $OS = "ubuntu" ]]; then
    console "Compiling on Ubuntu ($OS_VERSION)"
    sh <(curl -s https://smartpy.io/cli/install.sh)
  elif [[ $OS = "debian" ]]; then
    console "Compiling on Debian ($OS_VERSION)"
  else
    fail "Need install steps for your OS: ($OS_VERSION)"
  fi
fi

set -x
# install the smartPy CLI (if not currently present)
sh <(curl -s https://smartpy.io/cli/install.sh)
# create the output dir
mkdir -p $OUTPUT_DIR/
# first let's test the script to ensure no build errors as a sanity check
$HOME/smartpy-cli/SmartPy.sh test $SMARTPY_CONTRACT $OUTPUT_DIR/
# then proceed to compile the smartPy script in the target output directory
$HOME/smartpy-cli/SmartPy.sh compile $SMARTPY_CONTRACT $OUTPUT_DIR/
# identify the contract using the latest HEAD 
cp $OUTPUT_DIR/compiled_contract/*_contract.tz $CONTRACT_TARGET_DIR/zkchannel_contract_${COMMIT_HASH}.tz
# clean up 
rm -rf $OUTPUT_DIR
set +x