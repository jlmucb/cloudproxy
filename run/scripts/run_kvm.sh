#!/bin/bash

if [ "$#" != "3" ]; then
	echo "Must supply a CoreOS image, an SSH auth keys file, and a domain path"
	exit 1
fi

set -o nounset
set -o errexit

IMG=$1
KEYS=$2
DOMAIN=$3
BINDIR=${GOPATH}/bin

# Make sure we have sudo privileges before running anything.
sudo test true

# Start linux_host in KVM mode.
sudo ${BINDIR}/linux_host -hosted_program_type kvm_coreos -kvm_coreos_img $IMG \
	-kvm_coreos_ssh_auth_keys $KEYS -config_path ${DOMAIN}/tao.config \
	-pass BogusPass &
HOSTPID=$!

echo "Waiting for the hypervisor Linux Host to start"
sleep 2

# Set up the linux_host bundle for the VM.
SCRIPT_DIR=$(readlink -e $(dirname $0))
${SCRIPT_DIR}/build_linux_host.sh ${DOMAIN}/policy_keys/cert \
	${DOMAIN}/tao.config

echo "About to start a virtual machine as a hosted program"
# Start the VM with linux_host.
LHTEMP=`mktemp -d /tmp/kvm_linux_host.XXXXXXXX`
SSHPORT=2222
${BINDIR}/tao_launch -sock ${DOMAIN}/linux_tao_host/admin_socket \
	${BINDIR}/linux_host.img.tgz ${LHTEMP} ${SSHPORT}

echo "Waiting for the virtual machine to start"
sleep 10
# Move the binaries to the temporary directory, which is mounted using Plan9P on
# the virtual machine.
cp ${BINDIR}/demo_server ${BINDIR}/demo_client ${BINDIR}/tao_launch ${LHTEMP}

# Run tao_launch twice across SSH to start the demo programs. For the ssh
# command to work, this session must have an ssh agent with the keys from
# ${KEYS}.
ssh -l core -p ${SSHPORT} localhost /media/tao/tao_launch \
	-sock /media/tao/linux_tao_host/admin_socket /media/tao/demo_server \
	-config /media/tao/tao.config

echo Waiting for the server to start
sleep 2

ssh -l core -p ${SSHPORT} localhost /media/tao/tao_launch \
	-sock /media/tao/linux_tao_host/admin_socket /media/tao/demo_client \
	-config /media/tao/tao.config -host 127.0.0.1
echo Waiting for the client to run
sleep 4

scp -P ${SSHPORT} core@localhost:/tmp/demo_client.INFO /tmp/demo_client.INFO
scp -P ${SSHPORT} core@localhost:/tmp/demo_server.INFO /tmp/demo_server.INFO
echo -e "\n\nClient output:"
cat /tmp/demo_client.INFO

echo -e "\n\nServer output:"
cat /tmp/demo_server.INFO

echo -e "\n\nCleaning up"
ssh -l core -p ${SSHPORT} localhost sudo shutdown -h now
sudo kill $HOSTPID
sudo rm -fr $LHTEMP /tmp/demo_server.INFO /tmp/demo_client.INFO
