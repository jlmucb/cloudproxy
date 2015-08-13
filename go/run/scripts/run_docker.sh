#!/bin/bash

set -o nounset
set -o errexit

if [ "$#" -ge 1 ]; then
  export TAO_DOMAIN="$1"
elif [ "$TAO_DOMAIN" == "" ]; then
	echo "Must supply the path to an initialized domain, or set \$TAO_DOMAIN."
	exit 1
fi

gowhich() {
	WHICH=$(which which)
	echo -n "$(PATH="${GOPATH//://bin:}/bin" $WHICH "$1")"
}

TAO="$(gowhich tao)"
FAKE_PASS=BogusPass

CLIENT="$(gowhich demo_client).img.tgz"
SERVER="$(gowhich demo_server).img.tgz"

# Make sure we have sudo privileges before trying to start the tao host
sudo test true

sudo "$TAO" host start -tao_domain "$TAO_DOMAIN" -pass $FAKE_PASS \
	-hosting docker &

echo "Waiting for linux_host to start"
sleep 5

"$TAO" run "docker:$SERVER" &

echo "Waiting for docker to update its list of running containers"
sleep 2
container_name=$(sudo docker inspect --format='{{.Name}}' $(sudo docker ps -q -l))
container_name=${container_name#/} # this removes the leading slash

"$TAO" run "docker:$CLIENT" --link "${container_name}:server"

echo "Waiting for the tests to complete"
sleep 5

echo "Cleaning up docker containers"
sudo docker stop $container_name

echo "Shutting down linux_host"
sudo "$TAO" host stop -tao_domain "$TAO_DOMAIN"
