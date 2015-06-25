#!/bin/bash

# This script assumes that the binary for linux_host has been built and
# installed into a bin path in $GOPATH. For the purposes of KVM/CoreOS, this
# binary must be executable on the virtual machine. One way to make this easier
# is to build the binary statically. E.g., see run/scripts/build_standalone.sh.

if [ "$#" != "2" ]; then
	echo "Must supply a policy certificate and a tao.config for the VM linux_host"
	exit 1
fi

WHICH=$(which which)
APP_BIN="$(PATH="${GOPATH//://bin:}/bin" $WHICH linux_host)"
TEMP_DIR=$(mktemp -d)
cp "$APP_BIN" ${TEMP_DIR}/linux_host
mkdir ${TEMP_DIR}/policy_keys
mkdir ${TEMP_DIR}/linux_tao_host
chmod 755 ${TEMP_DIR}/linux_tao_host
cp "$1" ${TEMP_DIR}/policy_keys/cert
cp "$2" ${TEMP_DIR}/tao.config

tar -C ${TEMP_DIR} -czf "$APP_BIN".img.tgz $(ls ${TEMP_DIR})
rm -fr ${TEMP_DIR}
