#!/bin/sh

SCRIPTS=/home/tmroeder/src/fileProxy/Code/scripts

# this script assumes that keyNegoServer and tcService are running and that the
# kernel module has been loaded (a prerequisite of running tcService)

rm authServer/*
./authServer.exe -initProg
sleep 2

# provision the authServer with a signing key
$SCRIPTS/provisionAuthServer.py

./authServer.exe -initProg
sleep 2

# check to make sure it was able to get the port
grep "top of accept loop" authServer.log
status=$?
if [ $status -ne 0 ]; then
  echo "authServer provisioning failed. Maybe wait for the port to be free?"
  exit $status
else
  echo "Provisioning succeded"
fi
