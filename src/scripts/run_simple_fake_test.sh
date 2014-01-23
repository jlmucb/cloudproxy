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
sleep 5
# Request that the LinuxTao start the CloudServer program
./start_hosted_program --program server
sleep 2
# Request that the LinuxTao start the CloudClient program
./start_hosted_program --program client

sleep 5

# kill the services the painful way
# TODO(tmroeder): this should really stop the services cleanly
kill $tcca_pid
kill $service_pid

server_pid=`pgrep -l server | sed 's/^\([0-9][0-9]*\) server$/\1/g' | grep -v "[a-zA-Z]"`
kill $server_pid

rm /tmp/.linux_tao_s*
