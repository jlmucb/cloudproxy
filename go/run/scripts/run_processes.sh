#!/bin/sh

if [ "$#" != "1" ]; then
	echo "Must supply the path to an initialized domain"
	exit 1
fi

set -o nounset
set -o errexit

DOMAIN=$1
BINDIR=${GOPATH}/bin

# Make sure we have sudo privileges before using them to try to start linux_host
# below.
sudo test true

sudo ${BINDIR}/linux_host -config_path ${DOMAIN}/tao.config -pass BogusPass &
HOSTPID=$!

echo "Waiting for linux_host to start"
sleep 5

DSPID=$(${BINDIR}/tao_launch -sock ${DOMAIN}/linux_tao_host/admin_socket \
	${BINDIR}/demo_server -config=${DOMAIN}/tao.config)
${BINDIR}/tao_launch -sock ${DOMAIN}/linux_tao_host/admin_socket \
	${BINDIR}/demo_client -config=${DOMAIN}/tao.config > /dev/null


echo "Waiting for the tests to finish"
sleep 5

echo "\n\nClient output:"
cat /tmp/demo_client.INFO

echo "\n\nServer output:"
cat /tmp/demo_server.INFO

echo "Cleaning up remaining programs"
kill $DSPID
sudo kill $HOSTPID
sudo rm -f ${DOMAIN}/linux_tao_host/admin_socket
