#!/bin/bash
#first arg is the port number for this
#second arg is the prebuilt circuit for testing
#third arg is the dest addr

./initmixnet.sh
source ./define.sh

# These should be run as root.
$GOPATH/bin/tao host init -tao_domain $DOMAIN -hosting process -root -pass $PASSWORD
sudo -E $GOPATH/bin/tao host start -tao_domain $DOMAIN -host linux_tao_host -pass $PASSWORD &
sleep 2

directory_file=/tmp/directories

echo "Starting proxy..."
$GOPATH/bin/tao run -tao_domain $DOMAIN $DOMAINROOT/mixnet_proxy -dirs $directory_file --config $DOMAIN/tao.config --addr :$1 --circuit $2&
sleep 0.5

$DOMAINROOT/mixnet_simpleclient --proxy_addr 127.0.0.1:$1 --dest_addr $3
