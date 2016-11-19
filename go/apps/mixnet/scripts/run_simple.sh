#!/bin/sh
source ./define.sh

# These should be run as root.
$GOPATH/bin/tao host init -tao_domain $DOMAIN -hosting process -root -pass xxx
sudo -E $GOPATH/bin/tao host start -tao_domain $DOMAIN -host linux_tao_host -pass xxx &
sleep 2

#
# Starting the programs should be done as the unprivileged user it runs for
# to provide isolation.
# We run as root for conveniencea to avoid script clutter.
#
dir_addr="127.0.0.1:8000"
start_port=8001
echo "Starting directory..."
$GOPATH/bin/tao run -tao_domain $DOMAIN $DOMAINROOT/mixnet_directory --addr $dir_addr --config $DOMAIN/tao.config &
sleep 0.5

$GOPATH/bin/tao run -tao_domain $DOMAIN $DOMAINROOT/mixnet_router --addr 127.0.0.1:$start_port --dir_addr $dir_addr --config $DOMAIN/tao.config --batch 1 &
sleep 0.3

echo -e "127.0.0.1:8001" > $DOMAIN/mixnet_proxy/1.circuit

# Start mixnet proxies; proxies will pick one of 4 paths
proxy_start_port=9000
echo "Starting proxies..."
$GOPATH/bin/tao run -tao_domain $DOMAIN $DOMAINROOT/mixnet_proxy --addr :$proxy_start_port --config $DOMAIN/tao.config --circuit $DOMAIN/mixnet_proxy/1.circuit &
sleep 0.3

# Start echo TLS server
dest_port=10000
echo "Starting echo TLS server..."
$DOMAINROOT/mixnet_simpleserver --addr :$dest_port --cert $DOMAIN/mixnet_simpleserver/cert.pem --key $DOMAIN/mixnet_simpleserver/key.pem&
sleep 0.3

# Start all the clients
echo "Starting simpleclients..."
$DOMAINROOT/mixnet_simpleclient --proxy_addr 127.0.0.1:$proxy_start_port --dest_addr 127.0.0.1:$dest_port --id 0
sleep 0.3

sudo pkill -f "$DOMAIN"
