#!/bin/sh

# Don't use uninitialized variables
set -o nounset

# Stop as soon as any command returns an error
set -o errexit

# Make sure we have sudo privileges before using them to try to start linux_host
# below.
sudo test true

TEMP_FILE=`mktemp /tmp/loc.XXXXXXXX`
sudo ${GOPATH}/bin/linux_host -tmppath=$TEMP_FILE &
HOSTPID=$!

echo "Waiting for linux_host to start"
sleep 5

DIR=`cat $TEMP_FILE`

# Authorize the applications
${GOPATH}/bin/tao_admin -config_path=${DIR}/tao.config -pass=BogusPass 

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
