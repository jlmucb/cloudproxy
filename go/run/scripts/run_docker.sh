#!/bin/bash

if [ "$#" != "3" ]; then
	echo "Must supply a path to an initialized domain, along with client and server images for Docker"
	exit 1
fi

set -o nounset
set -o errexit

gowhich() {
	WHICH=$(which which)
	echo -n "$(PATH="${GOPATH//://bin:}/bin" $WHICH "$1")"
}

DOMAIN="$1"
CLIENT="$2"
SERVER="$3"

# Make sure we have sudo privileges before trying to use them to start
# linux_host below.
sudo test true

sudo "$(gowhich linux_host)" -config_path ${DOMAIN}/tao.config \
	-hosted_program_type=docker &
HOSTPID=$!

echo "Waiting for linux_host to start"
sleep 5

"$(gowhich tao_launch)" -sock ${DOMAIN}/linux_tao_host/admin_socket -docker_img \
	"$SERVER" -- "$SERVER"
echo "Waiting for docker to update its list of running containers"
sleep 2
container_name=$(sudo docker inspect --format='{{.Name}}' $(sudo docker ps -q -l))
container_name=${container_name#/} # this removes the leading slash
"$(gowhich tao_launch)" -sock ${DOMAIN}/linux_tao_host/admin_socket -docker_img \
	"$CLIENT" -- "$CLIENT" --link ${container_name}:server

echo "Waiting for the tests to complete"
sleep 5

echo "Cleaning up docker containers"
sudo docker stop $container_name
sudo kill $HOSTPID
sudo rm -f ${DOMAIN}/linux_tao_host/admin_socket
