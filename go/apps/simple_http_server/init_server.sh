#!/bin/sh
# Change these exports to run it under different folder
export DOMAIN=./Domain
export BINPATH=$GOPATH/bin
export TEMPLATE=allowall.cfg
export PASSWORD=xxx #password for SoftTao

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

if [[ -e $DOMAIN/simpleserver ]]
then
  echo "$DOMAIN/simpleserver exists"
else
  mkdir $DOMAIN/simpleserver
  echo "$DOMAIN/simpleserver created"
fi

if [[ -e $DOMAIN/linux_tao_host ]]
then
  echo "$DOMAIN/linux_tao_host exists"
else
  mkdir $DOMAIN/linux_tao_host
  echo "$DOMAIN/linux_tao_host created"
fi


$BINPATH/tao domain init -tao_domain $DOMAIN -config_template $TEMPLATE \
  -pub_domain_address "127.0.0.1" -pass $PASSWORD

#
# The following line is not needed since we have a liberal guard.
# $BINPATH/tao domain policy -add_host -add_programs -add_linux_host -add_guard -tao_domain \
#      $DOMAIN -pass xxx -config_template $TEMPLATE
# If we had a restrictive guard, we'd have to call this command to create rules for the linux_host.


# These should be run as root.
# Start linux host SoftTao
sudo -E $BINPATH/tao host init -tao_domain $DOMAIN -hosting process -root -pass $PASSWORD
sleep 3
sudo -E $BINPATH/tao host start -tao_domain $DOMAIN -host linux_tao_host -pass $PASSWORD &
sleep 3

# start the http server
$BINPATH/tao run -tao_domain $DOMAIN \
  $DOMAIN/http_server -domain_config $DOMAIN/tao.config -path $DOMAIN/simpleserver

#clean up..
sudo rm -f $DOMAIN/linux_tao_host/admin_socket

#WARNING: THE FOLLOWING COMMAND WILL KILL EVERYTHING WITH $DOMAIN IN THE PROCESS NAME
#If you are sure there are no other processes with domain in the name,
#you can use this to clear all tao related processess
#sudo pkill -f $DOMAIN
