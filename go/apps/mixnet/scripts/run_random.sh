#!/bin/bash
source ./define.sh

# These should be run as root.
$GOPATH/bin/tao host init -tao_domain $DOMAIN -hosting process -root -pass $PASSWORD
sudo -E $GOPATH/bin/tao host start -tao_domain $DOMAIN -host linux_tao_host -pass $PASSWORD &
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

directory_file=/tmp/directories
echo $dir_addr > $directory_file

# Start 6 routers
router_pids=""
echo "Starting routers..."
for i in `seq 0 5`;
do
  port=$[$start_port+$i]
  $GOPATH/bin/tao run -tao_domain $DOMAIN $DOMAINROOT/mixnet_router --addr 127.0.0.1:$port --dirs $directory_file --config $DOMAIN/tao.config --batch 2 &
  router_pids="$router_pids $!"
  sleep 0.3
done

# Start mixnet proxies; proxies will pick one of 4 paths
proxy_start_port=9000
proxy_pids=""
echo "Starting proxies..."
for i in `seq 0 15`;
do
  port=$[$proxy_start_port+$i]
  $GOPATH/bin/tao run -tao_domain $DOMAIN $DOMAINROOT/mixnet_proxy --addr :$port --dirs $directory_file --config $DOMAIN/tao.config --hops 3 &
  proxy_pids="$proxy_pids $!"
  sleep 0.3
done

# Start echo TLS server
dest_port=10000
echo "Starting echo TLS server..."
$DOMAINROOT/mixnet_simpleserver --addr :$dest_port --cert $DOMAIN/mixnet_simpleserver/cert.pem --key $DOMAIN/mixnet_simpleserver/key.pem &
dest_pid=$!
sleep 0.3

# Start all the clients
clients_pids=""
echo "Starting simpleclients..."
for i in `seq 0 15`;
do
  port=$[$proxy_start_port+$i]
  $DOMAINROOT/mixnet_simpleclient --proxy_addr 127.0.0.1:$port --dest_addr 127.0.0.1:$dest_port --id $i&
  clients_pids="$clients_pids $!"
done

for pid in $clients_pids; do
    wait $pid
done

for pid in $proxy_pids; do
  kill $pid
done

for pid in $router_pids; do
  kill $pid
done

kill $dest_pid

#sudo pkill -f "$DOMAIN"
