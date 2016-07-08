#!/bin/bash

if [ "$#" -ge 1 ]; then
    export DOMAIN_TEMPLATE="$1"
elif [ "$DOMAIN_TEMPLATE" == "" ]; then
	  echo "Must supply the path to a domain template, or set \$DOMAIN_TEMPLATE."
	  exit 1
fi

set -o nounset
set -o errexit

gowhich() {
	  WHICH=$(which which)
	  echo -n "$(PATH="${GOPATH//://bin:}/bin" $WHICH "$1")"
}

TAO="$(gowhich tao)"
ENDORSEMENT="$(gowhich Endorsement)"
QUOTE="$(gowhich QuoteServer)"
FAKE_PASS=BogusPass
DOMAIN_TEMPLATE="$(readlink -f $DOMAIN_TEMPLATE)"

# Make sure we have sudo privileges before trying to start the tao host
sudo test true

# Create new domain
if [ -d /tmp/temp_domain ]; then
    echo "Error: Tao domain directoty /tmp/temp_domain already exists."
    exit 1
fi
mkdir /tmp/temp_domain
cd /tmp/temp_domain
"$TAO" domain init -tao_domain . -pass $FAKE_PASS -config_template $DOMAIN_TEMPLATE

if [ ! -d ./policy_keys ]; then
    echo "Error: Policy key not found"
    exit 1
fi
echo "Policy key created"

# Create endorsement cert
sudo $ENDORSEMENT -policy_key_is_ecdsa -policy_key_dir ./policy_keys -endorsement_save_file endorsement_cert -policy_key_password $FAKE_PASS

if [ ! -f ./endorsement_cert ]; then
    echo "Error: Endorsement cert not found"
    exit 1
fi

# Start Quote Server
$QUOTE -pass $FAKE_PASS -path ./policy_keys &
echo
echo "Quote server running"

# Start host
sudo "$TAO" host init -tao_domain . -stacked -parent_type TPM2 -hosting process
sudo "$TAO" host start -tao_domain . &

echo
echo "Remember to flush open TPM handles, kill the host and Quote server, and remove /tmp/temp_domain"





