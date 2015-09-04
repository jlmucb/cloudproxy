#!/bin/bash

if [ "$#" -ge 1 ]; then
  export TAO_DOMAIN="$1"
elif [ "$TAO_DOMAIN" == "" ]; then
	echo "Must supply the path to an initialized domain, or set \$TAO_DOMAIN."
	exit 1
fi

set -o nounset
set -o errexit

gowhich() {
	WHICH=$(which which)
	echo -n "$(PATH="${GOPATH//://bin:}/bin" $WHICH "$1")"
}

TAO="$(gowhich tao)"
FAKE_PASS=BogusPass

# Make sure we have sudo privileges before trying to start the tao host
sudo test true

sudo "$TAO" host start -tao_domain "$TAO_DOMAIN" -pass $FAKE_PASS \
  -hosting process,docker &

echo "Waiting for linux_host to start"
sleep 5

# Run demo as linux processes

"$TAO" run demo_server &
sleep 2
"$TAO" run demo_client

# Run demo as docker images

CLIENT="$(gowhich demo_client).img.tgz"
SERVER="$(gowhich demo_server).img.tgz"

"$TAO" run "docker:$SERVER" --name "/demo_server" & # daemon
echo "Waiting for demo_server to start"
sleep 3

"$TAO" run "docker:$CLIENT" --link "/demo_server:server"


echo "Shutting down linux_host"
sudo "$TAO" host stop -tao_domain "$TAO_DOMAIN"
