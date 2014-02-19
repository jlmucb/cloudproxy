#!/bin/bash

# BEFORE RUNNING: use src/scripts/setup_keys.sh to set up new keys, and cd to
# the TEST directory from that script.

# Start the relevant pieces of code:
# The Trusted Computing Certificate Authority
bin/tcca &
tcca_pid=$!
sleep 1
# The LinuxTao
bin/linux_tao_service --aik_blob tpm/aikblob --aik_attestation tpm/aik.attest &
service_pid=$!
sleep 4
# Request that the LinuxTao start the CloudServer program

server_pid=`bin/start_hosted_program --program bin/server`
sleep 2
# Request that the LinuxTao start the CloudClient program
client_pid=`bin/start_hosted_program --program bin/client`

sleep 4

# kill the services the painful way

echo "Test is over, killing processes"
# TODO(tmroeder): this should really stop the services cleanly
# This stops tcca cleanly, since tcca has a SIGTERM handler
kill $tcca_pid

# Send a stop message to the linux service. The default socket works.
bin/stop_service

kill $server_pid

rm -f /tmp/.linux_tao_s*

echo "Success!"
