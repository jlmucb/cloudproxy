#!/bin/bash

if [ "$#" -ge 1 ]; then
	export TAO_DOMAIN="$1"
elif [ "$TAO_DOMAIN" == "" ]; then
	echo "Must supply the path to an initialized domain, or set \$TAO_DOMAIN."
	exit 1
fi

if [ "$#" -ge 2 ]; then
	export CA_ADDR="$2"
else
	echo "Must supply an address for the TaoCA."
	exit 1
fi

# The TaoCA accesses the domain policy.
CA_TAO_DOMAIN=${TAO_DOMAIN}

# LinuxHost and applications use the public policy.
TAO_DOMAIN="${TAO_DOMAIN}.pub"

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

echo "Staring TaoCA"
"$(gowhich tcca)" -config "${CA_TAO_DOMAIN}/tao.config" -password $FAKE_PASS -addr $CA_ADDR &
sleep 1

echo "Starting LinuxHost"
sudo "$TAO" host start -tao_domain "$TAO_DOMAIN" -pass $FAKE_PASS &
sleep 2

SERVER_MSG="Who is this?"
CLIENT_MSG="I am the enigma."

echo "Starting a test server"
(echo "$SERVER_MSG" | $(which nc) -l 8080 > /tmp/serverout) &

echo "Starting Mixnet Router"
"$TAO" run mixnet_router -config "${TAO_DOMAIN}/tao.config" &
sleep 1

echo "Starting Mixnet Proxy"
"$(gowhich mixnet_proxy)" -config "${TAO_DOMAIN}/tao.config" &
sleep 1

echo "Starting a client"
echo "$CLIENT_MSG" | $(which nc) 127.0.0.1 8080 -X 5 -x 127.0.0.1:1080 > /tmp/clientout

if [ "$(cat /tmp/serverout)" != "$CLIENT_MSG" ]; then
	echo "Server got the wrong message: $(cat /tmp/serverout)"
else
	echo "Server passed!"
fi
if [ "$(cat /tmp/clientout)" != "$SERVER_MSG" ]; then
	echo "Client got the wrong message: $(cat /tmp/clientout)"
else
	echo "Client passed!"
fi

echo "Cleaning up"
sudo "$TAO" host stop -tao_domain "$TAO_DOMAIN"
killall $(gowhich tcca)
killall $(gowhich mixnet_proxy)
