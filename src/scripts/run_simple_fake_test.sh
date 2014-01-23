#!/bin/bash

# BEFORE RUNNING: use src/scripts/setup_keys.sh to set up new keys, and cd to
# the TEST directory from that script.


# Start the relevant pieces of code:
# The Trusted Computing Certificate Authority
./tcca &
tcca_pid=$!
sleep 1
# The LinuxTao
./linux_tao_service --ca_host localhost --ca_port 11238 --nouse_tpm &
service_pid=$!
sleep 4
# Request that the LinuxTao start the CloudServer program
server_pid=`./start_hosted_program --program server`
sleep 2
# Request that the LinuxTao start the CloudClient program
client_pid=`./start_hosted_program --program client`

sleep 4

# This stops tcca cleanly, since tcca has a SIGTERM handler
kill $tcca_pid

# Send a stop message to the linux service. The default socket works.
./stop_service

kill $server_pid

rm -f /tmp/.linux_tao_s*
