#!/bin/bash

# This script assumes that the binary for linux_host has been built and
# installed into ${GOPATH}/bin/linux_host. For the purposes of KVM/CoreOS, this
# binary must be executable on the virtual machine. One way to make this easier
# is to build the binary statically. E.g., see apps/demo/build_standalone.sh.

if [ "$#" != "1" ]; then
	echo "Must supply a policy certificate for the VM linux_host"
	exit 1
fi

LINUX_HOST_DIR=$(readlink -e $(dirname $0))
TEMP_DIR=`mktemp -d`
cp ${GOPATH}/bin/linux_host ${TEMP_DIR}/linux_host
mkdir ${TEMP_DIR}/policy_keys
cp $1 ${TEMP_DIR}/policy_keys/cert
cat >${TEMP_DIR}/tao.config <<EOF
# Tao Domain Configuration file

[Domain]
Name = testing
PolicyKeysPath = policy_keys
GuardType = AllowAll

[X509Details]
CommonName = testing	
EOF

tar -C ${TEMP_DIR} -czf ${LINUX_HOST_DIR}/linux_host.img.tgz `ls ${TEMP_DIR}`

