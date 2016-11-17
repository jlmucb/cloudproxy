#!/bin/sh
# Change these exports to run it under different folder
export DOMAIN=./Domain # Root domain
export BINPATH=$GOPATH/bin # Where to find the relevant bins
export TEMPLATE=allowall.cfg # Tao configuration template
export PASSWORD=httptest #password for SoftTao

# Build all the source
go install ./...

if [[ -e $DOMAIN ]]
then
  echo "$DOMAIN exists"
else
  mkdir $DOMAIN
  mkdir $DOMAIN/policy_keys
  echo "$DOMAIN created"
fi

# copy the relevant files to domain
cp $BINPATH/simple_http_server $DOMAIN/http_server
cp $TEMPLATE $DOMAIN/

# Create a domain for the server; server relevant files are stored here.
if [[ -e $DOMAIN/simpleserver ]]
then
  echo "$DOMAIN/simpleserver exists"
else
  mkdir $DOMAIN/simpleserver
  echo "$DOMAIN/simpleserver created"
fi

# Create a domain for the linux_host
if [[ -e $DOMAIN/linux_tao_host ]]
then
  echo "$DOMAIN/linux_tao_host exists"
else
  mkdir $DOMAIN/linux_tao_host
  echo "$DOMAIN/linux_tao_host created"
fi

# Create the key for SoftTao. This generates a cert and a private key
# for SoftTao, and put it in $DOMAIN/linux_tao_host
KEY_NAME="$($BINPATH/tao domain newsoft -soft_pass $PASSWORD \
  -config_template $DOMAIN/$TEMPLATE $DOMAIN/linux_tao_host)"
echo "host_name: \"$KEY_NAME\"" | tee -a $DOMAIN/$TEMPLATE

# Create the domain and relevant files
# Create policy keys that can be used to sign and authenticate different
# policies that can be used to determine which code runs.
# Without a liberal guard, one should run something like to generate correct policies.
# $BINPATH/tao domain policy -add_host -add_programs -add_linux_host -add_guard -tao_domain \
#      $DOMAIN -pass xxx -config_template $DOMAIN/$TEMPLATE
$BINPATH/tao domain init -tao_domain $DOMAIN -config_template $DOMAIN/$TEMPLATE \
  -pub_domain_address "127.0.0.1" -pass $PASSWORD

# Produces a certificate for SoftTao root key. In a real deployment, this will
# be replaced by TPM certificates. This also specifies the type of applications
# that will be hosted. In this example, it's "process", but could be containers
# or something else.
$BINPATH/tao host init -tao_domain $DOMAIN -hosting process -root -pass $PASSWORD

# Start linux host on SoftTao. Needs to run as root to
sudo -E $BINPATH/tao host start -tao_domain $DOMAIN -host linux_tao_host -pass $PASSWORD &
sleep 3

# Start the http server
$BINPATH/tao run -tao_domain $DOMAIN \
  $DOMAIN/http_server -domain_config $DOMAIN/tao.config -path $DOMAIN/simpleserver

# clean up..
# sudo rm -f $DOMAIN/linux_tao_host/admin_socket
# WARNING: THE FOLLOWING COMMAND WILL KILL EVERYTHING WITH $DOMAIN IN THE PROCESS NAME
# If you are sure there are no other processes with domain in the name,
# you can use this to clear all tao related processess
# pkill -f $DOMAIN
