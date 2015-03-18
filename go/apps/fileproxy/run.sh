#!/bin/bash

set -o nounset
set -o errexit

BINDIR=${GOPATH}/bin
SCRIPT_DIR=$(readlink -e $(dirname $0))

echo "Script dir is ${SCRIPT_DIR}"

# Make sure we have sudo credentials before running linux_host.
sudo test true

t=`mktemp /tmp/loc.XXXXXXXX`
sudo ${BINDIR}/linux_host -tmppath=$t &
hostpid=$!

echo "Waiting for linux_host to start"
sleep 2

# Go to the temp directory set up by linux_host.
DIR=`cat $t`
cd ${DIR}

# Set up the key server.
sudo ${BINDIR}/keynegoserver -password=BogusPass &
knpid=$!
echo "Waiting for the keynegoserver to start"
sleep 2

${BINDIR}/tao_launch -sock ${DIR}/linux_tao_host/admin_socket -- \
	${BINDIR}/rollbackserver -hostconfig=${DIR}/tao.config \
	-rollbackserver_files=${DIR}/rollbackserver_files
echo "Waiting for the rollback server to start"
sleep 2

${BINDIR}/tao_launch -sock ${DIR}/linux_tao_host/admin_socket -- \
	${BINDIR}/fileserver -hostconfig=${DIR}/tao.config \
	-fileserver_files=${DIR}/fileserver_files
echo "Waiting for the fileserver to start"
sleep 2

# Create a user and start the test client
sudo ${BINDIR}/tao_admin -operation user \
	-user_key_details=${SCRIPT_DIR}/user.pb -user_pass=BogusPass \
	-user_key_path=${DIR}/usercreds -pass BogusPass

${BINDIR}/tao_launch -sock ${DIR}/linux_tao_host/admin_socket -- \
	${BINDIR}/fileclient -hostconfig=${DIR}/tao.config \
	-fileclient_files=${DIR}/fileclient_files -usercreds=${DIR}/usercreds
sudo chmod 644 ${DIR}/usercreds/signer

echo "Waiting for the tests to finish"
sleep 5

echo "Cleaning up remaining programs"
pids=`${BINDIR}/tao_launch -sock ${DIR}/linux_tao_host/admin_socket -operation=list | cut -d' ' -f1 | head -n -1 | sed 's/^pid=//g'`
for p in $pids; do
	kill $p
done
sudo kill $knpid $hostpid
