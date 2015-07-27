#!/bin/bash

set -o nounset
set -o errexit

gowhich() {
	WHICH=$(which which)
	echo -n "$(PATH="${GOPATH//://bin:}/bin" $WHICH "$1")"
}

BINDIR=${GOPATH}/bin
SCRIPT_DIR=$(readlink -e $(dirname $0))

echo "Script dir is ${SCRIPT_DIR}"

# Make sure we have sudo credentials before running linux_host.
sudo test true

umask 022 # some dists use umask 077, but we need 022
DIR=`mktemp -d /tmp/fileproxy_domain.XXXXXX`
sudo "$(gowhich linux_host)" -temp_trivial_domain=${DIR} &
hostpid=$!

echo "Waiting for linux_host to start"
sleep 2

# Go to the temp directory set up by linux_host.
cd ${DIR}

# Set up the key server.
sudo "$(gowhich keynegoserver)" -password=BogusPass &
knpid=$!
echo "Waiting for the keynegoserver to start"
sleep 2

"$(gowhich tao_launch)" -sock ${DIR}/linux_tao_host/admin_socket -- \
	"$(gowhich rollbackserver)" -hostconfig=${DIR}/tao.config \
	-rollbackserver_files=${DIR}/rollbackserver_files
echo "Waiting for the rollback server to start"
sleep 2

"$(gowhich tao_launch)" -sock ${DIR}/linux_tao_host/admin_socket -- \
	"$(gowhich fileserver)" -hostconfig=${DIR}/tao.config \
	-fileserver_files=${DIR}/fileserver_files
echo "Waiting for the fileserver to start"
sleep 2

# Create a user and start the test client
sudo "$(gowhich tao_admin)" -operation user \
	-user_key_details=${SCRIPT_DIR}/user.pb -user_pass=BogusPass \
	-user_key_path=${DIR}/usercreds -pass BogusPass

"$(gowhich tao_launch)" -sock ${DIR}/linux_tao_host/admin_socket -- \
	"$(gowhich fileclient)" -hostconfig=${DIR}/tao.config \
	-fileclient_files=${DIR}/fileclient_files -usercreds=${DIR}/usercreds
sudo chmod 644 ${DIR}/usercreds/signer

echo "Waiting for the tests to finish"
sleep 5

echo "Cleaning up remaining programs"
pids=`"$(gowhich tao_launch)" -sock ${DIR}/linux_tao_host/admin_socket -operation=list | cut -d' ' -f1 | head -n -1 | sed 's/^pid=//g'`
for p in $pids; do
	kill $p
done
sudo kill $knpid $hostpid
