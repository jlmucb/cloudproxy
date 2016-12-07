#!/bin/bash
#first arg is the public facing IP of the router
#second arg is the batch size

./initmixnet.sh
source ./define.sh

# These should be run as root.
$GOPATH/bin/tao host init -tao_domain $DOMAIN -hosting process -root -pass $PASSWORD
sudo -E $GOPATH/bin/tao host start -tao_domain $DOMAIN -host linux_tao_host -pass $PASSWORD &
sleep 2

port="8000"
directory_file=/tmp/directories

echo "Starting router..."
$GOPATH/bin/tao run -tao_domain $DOMAIN $DOMAINROOT/mixnet_router --addr $1:$port --dirs $directory_file --config $DOMAIN/tao.config --batch $2
