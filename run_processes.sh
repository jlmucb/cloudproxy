#!/bin/sh

# Make sure we have sudo privileges before using them to try to start linux_host
# below.
sudo test true

TEMP_FILE=`mktemp /tmp/loc.XXXXXXXX`
echo "About to start linux_host. This requires super-user privileges"
sudo ${GOPATH}/bin/linux_host -tmppath=$TEMP_FILE &
status=$?
HOSTPID=$!
if [ "$status" != "0" ]; then
	echo "Couldn't start the linux_host in a temporary directory"
	exit 1
fi

echo "Waiting for linux_host to start"
sleep 5

DIR=`cat $TEMP_FILE`
DEMO_DIR=$(readlink -e $(dirname $0))
DSPID=$(${GOPATH}/bin/tao_launch -sock ${DIR}/linux_tao_host/admin_socket ${GOPATH}/bin/demo_server -config=${DIR}/tao.config)
${GOPATH}/bin/tao_launch -sock ${DIR}/linux_tao_host/admin_socket ${GOPATH}/bin/demo_client -config=${DIR}/tao.config > /dev/null


echo "Waiting for the tests to finish"
sleep 5

echo "\n\nClient output:"
cat /tmp/demo_client.INFO

echo "\n\nServer output:"
cat /tmp/demo_server.INFO

echo "Cleaning up remaining programs"
kill $DSPID
sudo kill $HOSTPID
rm -f $TEMP_FILE
