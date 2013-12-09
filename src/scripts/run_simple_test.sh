#!/bin/bash

# BEFORE RUNNING: use src/scripts/setup_keys.sh to set up new keys, and cd to
# the TEST directory from that script.


# Start the relevant pieces of code:
# The Trusted Computing Certificate Authority
./tcca &
sleep 1
# The LinuxTao
./linux_tao_service --ca_host localhost --ca_port 11238 --aik_blob $AIKBLOB \
    --aik_attestation HW/aik.attest &
sleep 5
# Request that the LinuxTao start the CloudServer program
./start_hosted_program --program server
sleep 2
# Request that the LinuxTao start the CloudClient program
./start_hosted_program --program client

