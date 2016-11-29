#!/bin/sh

./initmixnet.sh
source ./define.sh

# Start echo TLS server
dest_port=10000
echo "Starting echo TLS server..."
$DOMAINROOT/mixnet_simpleserver --addr :$dest_port --cert $DOMAIN/mixnet_simpleserver/cert.pem --key $DOMAIN/mixnet_simpleserver/key.pem
