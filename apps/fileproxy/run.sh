#!/bin/bash

t=`mktemp /tmp/loc.XXXXXXXX`
linux_host -tmppath=$t &
status=$?
hostpid=$!
if [ "$status" != "0" ]; then
	echo "Couldn't start the linux_host in a temporary directory"
	exit 1
fi

echo "Waiting for linux_host to start"
sleep 2

# Go to the temp directory set up by linux_host.
DIR=`cat $t`
cd ${DIR}

# Set up the key server.
${GOPATH}/bin/keynegoserver -password=BogusPass &
knpid=$!
echo "Waiting for the keynegoserver to start"
sleep 2

tao_launch -sock ${DIR}/linux_tao_host/admin_socket -- ${GOPATH}/bin/rollbackserver -hostconfig=${DIR}/tao.config -rollbackserver_files=${DIR}/rollbackserver_files
echo "Waiting for the rollback server to start"
sleep 2

tao_launch -sock ${DIR}/linux_tao_host/admin_socket -- ${GOPATH}/bin/fileserver -hostconfig=${DIR}/tao.config -fileserver_files=${DIR}/fileserver_files
echo "Waiting for the fileserver to start"
sleep 2

# Create a user and start the test client
${GOPATH}/bin/tao_admin -newuserkey -common_name="jlm" -pass=BogusPass

tao_launch -sock ${DIR}/linux_tao_host/admin_socket -- ${GOPATH}/bin/fileclient -hostconfig=${DIR}/tao.config -fileclient_files=${DIR}/fileclient_files -usercreds=${DIR}/usercreds

echo "Waiting for the tests to finish"
sleep 5

echo "Cleaning up remaining programs"
pids=`tao_launch -sock ${DIR}/linux_tao_host/admin_socket -operation=list | cut -d' ' -f1 | head -n -1 | sed 's/^pid=//g'`
for p in $pids; do
	kill $p
done
kill $knpid $hostpid
