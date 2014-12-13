#!/bin/bash

# This must be run in a directory created by install.sh.

# Set up the linux host and its environment and get it started.
scripts/setup.sh
scripts/start.sh

echo "Waiting for the Linux host to start"
sleep 5

# Set up the key server.
bin/keynegoserver -password=BogusPass &

# Set up the RollbackMaster and the ResourceMaster under the Tao.
scripts/host.sh ./bin/rollbackserver -hostconfig=tao.config
scripts/host.sh ./bin/fileserver -hostconfig=tao.config

# Create a user and start the test client.
bin/tao_admin -newuserkey -common_name="jlm" -pass=BogusPass
scripts/host.sh ./bin/fileclient -hostconfig=tao.config

