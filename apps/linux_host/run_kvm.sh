#!/bin/bash

if [ "$#" != "2" ]; then
	echo "Must supply KVM CoreOS image and SSH auth keys file"
	exit 1
fi

IMG=$1
KEYS=$2

# Start linux_host in KVM mode and get its directory.
t=`mktemp /tmp/loc.XXXXXXXX`
${GOPATH}/bin/linux_host -hosted_program_type=kvm_coreos -kvm_coreos_img=$IMG -kvm_coreos_ssh_auth_keys=$KEYS -tmppath=$t &
status=$?
hostpid=$!

echo "Waiting for the hypervisor Linux Host to start"
sleep 2

DIR=`cat $t`

# Set up the linux_host bundle for the VM.
LHDIR=$(readlink -e $(dirname $0))
${LHDIR}/build.sh ${DIR}/policy_keys/cert

echo "About to start a virtual machine as a hosted program"
# Start the VM with linux_host.
LHTEMP=`mktemp -d /tmp/kvm_linux_host.XXXXXXXX`
SSHPORT=2222
${GOPATH}/bin/tao_launch -sock ${DIR}/linux_tao_host/admin_socket ${LHDIR}/linux_host.img.tgz ${LHTEMP} ${SSHPORT}

echo "Waiting for the virtual machine to start"
sleep 10
# Move the binaries to the temporary directory, which is mounted using Plan9P on
# the virtual machine.
cp ${GOPATH}/bin/demo_server ${GOPATH}/bin/demo_client ${GOPATH}/bin/tao_launch ${LHTEMP}

# Run tao_launch twice across SSH to start the demo programs. For the ssh
# command to work, this session must have an ssh agent with the keys from
# ${KEYS}.
ssh -l core -p ${SSHPORT} localhost /media/tao/tao_launch -sock /media/tao/linux_tao_host/admin_socket /media/tao/demo_server -config /media/tao/tao.config

echo Waiting for the server to start
sleep 2

ssh -l core -p ${SSHPORT} localhost /media/tao/tao_launch -sock /media/tao/linux_tao_host/admin_socket /media/tao/demo_client -config /media/tao/tao.config -host 127.0.0.1
echo Waiting for the client to run
sleep 4

scp -P ${SSHPORT} core@localhost:/tmp/demo_client.INFO /tmp/demo_client.INFO
scp -P ${SSHPORT} core@localhost:/tmp/demo_server.INFO /tmp/demo_server.INFO
echo -e "\n\nClient output:"
cat /tmp/demo_client.INFO

echo -e "\n\nServer output:"
cat /tmp/demo_server.INFO

#echo -e "\n\nCleaning up"
#ssh -l core -p ${SSHPORT} localhost sudo shutdown -h now
#kill $hostpid
#rm -fr $t ${LHTEMP} /tmp/demo_server.INFO /tmp/demo_client.INFO
