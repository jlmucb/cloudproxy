#!/bin/sh

t=`mktemp /tmp/loc.XXXXXXXX`
linux_host -tmppath=$t &
status=$?
hostpid=$!
if [ "$status" != "0" ]; then
	echo "Couldn't start the linux_host in a temporary directory"
	exit 1
fi

echo "Waiting for linux_host to start"
sleep 5

DIR=`cat $t`
DEMO_DIR=$(readlink -e $(dirname $0))
tao_launch -sock ${DIR}/linux_tao_host/admin_socket -- ${GOPATH}/bin/demo_server -config=${DIR}/tao.config
tao_launch -sock ${DIR}/linux_tao_host/admin_socket -- ${GOPATH}/bin/demo_client -config=${DIR}/tao.config


echo "Waiting for the tests to finish"
sleep 5

echo "Cleaning up remaining programs"
pids=`tao_launch -sock ${DIR}/linux_tao_host/admin_socket -operation=list | cut -d' ' -f1 | head -n -1 | sed 's/^pid=//g'`
for p in $pids; do
	kill $p
done

kill $hostpid
