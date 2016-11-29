#!/bin/sh
./initmixnet.sh
source ./define.sh

# These should be run as root.
$GOPATH/bin/tao host init -tao_domain $DOMAIN -hosting process -root -pass $PASSWORD
sudo -E $GOPATH/bin/tao host start -tao_domain $DOMAIN -host linux_tao_host -pass $PASSWORD &
sleep 2

dir_addr="127.0.0.1:8000"
echo "Starting directory..."

$GOPATH/bin/tao run -tao_domain $DOMAIN $DOMAINROOT/mixnet_directory --addr $dir_addr --config $DOMAIN/tao.config
