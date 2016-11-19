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

# Start 6 routers
echo "Starting routers..."
for i in `seq 0 5`;
do
  port=$[$start_port+$i]
  $GOPATH/bin/tao run -tao_domain $DOMAIN $DOMAINROOT/mixnet_router --addr 127.0.0.1:$port --dir_addr $dir_addr --config $DOMAIN/tao.config --batch 8 &
  sleep 0.3
done

echo -e "127.0.0.1:8001\n127.0.0.1:8002\n127.0.0.1:8003" > $DOMAIN/mixnet_proxy/1.circuit
echo -e "127.0.0.1:8001\n127.0.0.1:8005\n127.0.0.1:8003" > $DOMAIN/mixnet_proxy/2.circuit
echo -e "127.0.0.1:8004\n127.0.0.1:8005\n127.0.0.1:8006" > $DOMAIN/mixnet_proxy/3.circuit
echo -e "127.0.0.1:8004\n127.0.0.1:8002\n127.0.0.1:8006" > $DOMAIN/mixnet_proxy/4.circuit

# Start mixnet proxies; proxies will pick one of 4 paths
proxy_start_port=9000
echo "Starting proxies..."
for i in `seq 0 15`;
do
  port=$[$proxy_start_port+$i]
  if [[ $(( $i % 4 )) == 0 ]]; then
    circuit="1.circuit"
  elif [[ $(( $i % 4 )) == 1 ]]; then
    circuit="2.circuit"
  elif [[ $(( $i % 4 )) == 2 ]]; then
    circuit="3.circuit"
  elif [[ $(( $i % 4 )) == 3 ]]; then
    circuit="4.circuit"
  fi
  $GOPATH/bin/tao run -tao_domain $DOMAIN $DOMAINROOT/mixnet_proxy --addr :$port --config $DOMAIN/tao.config --circuit $DOMAIN/mixnet_proxy/$circuit &
  sleep 0.3
done

# Start echo TLS server
dest_port=10000
echo "Starting echo TLS server..."
$DOMAINROOT/mixnet_simpleserver --addr :$dest_port --cert $DOMAIN/mixnet_simpleserver/cert.pem --key $DOMAIN/mixnet_simpleserver/key.pem&
sleep 0.3

# Start all the clients
pids=""
echo "Starting simpleclients..."
for i in `seq 0 15`;
do
  port=$[$proxy_start_port+$i]
  $DOMAINROOT/mixnet_simpleclient --proxy_addr 127.0.0.1:$port --dest_addr 127.0.0.1:$dest_port --id $i&
  pids="$pids $!"
done

for pid in $pids; do
    wait $pid || let "RESULT=1"
done

sudo pkill -f "$DOMAIN"
