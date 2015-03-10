#!/bin/sh

if [ "$#" != "1" ]; then
	echo "Must supply a path to an initialized domain"
	exit 1
fi

set -o nounset
set -o errexit

DOMAIN=$1
BINDIR=${GOPATH}/bin

# Make sure we have sudo privileges before trying to use them to start
# linux_host below.
sudo test true

sudo ${BINDIR}/linux_host -config_path ${DOMAIN}/tao.config \
	-hosted_program_type=docker &
HOSTPID=$!

echo "Waiting for linux_host to start"
sleep 5

${BINDIR}/tao_launch -sock ${DOMAIN}/linux_tao_host/admin_socket -docker_img \
	${BINDIR}/demo_server.img.tgz -- ${BINDIR}/demo_server.img.tgz
echo "Waiting for docker to update its list of running containers"
sleep 2
container_name=$(docker inspect $(docker ps -q -l) | grep Name | tail -1 | \
	cut -d' ' -f6 | sed 's?^"/\(.*\)",$?\1?g')
${BINDIR}/tao_launch -sock ${DOMAIN}/linux_tao_host/admin_socket -docker_img \
	${BINDIR}/demo_client.img.tgz -- ${BINDIR}/demo_client.img.tgz \
	--link ${container_name}:server

echo "Waiting for the tests to complete"
sleep 5

echo "Cleaning up docker containers"
docker stop $container_name
sudo kill $HOSTPID
