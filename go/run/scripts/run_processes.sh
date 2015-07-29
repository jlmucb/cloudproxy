#!/bin/bash

if [ "$#" == "0" -a "$TAO_DOMAIN" != "" ]; then
  DOMAIN="$TAO_DOMAIN"
elif [ "$#" == "1" ]; then
  DOMAIN="$1"
else
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

# Make sure we have sudo privileges before using them to try to start linux_host
# below.
sudo test true

sudo "$TAO" host start -tao_domain "$DOMAIN" -pass $FAKE_PASS &

echo "Waiting for linux_host to start"
sleep 5

"$TAO" run -tao_domain "$DOMAIN" "$(gowhich demo_server)" -config "$DOMAIN/tao.config" &
"$TAO" run -tao_domain "$DOMAIN" "$(gowhich demo_client)" -config "$DOMAIN/tao.config"

echo "Shutting down linux_host"
sudo "$TAO" host stop -tao_domain "$DOMAIN"
