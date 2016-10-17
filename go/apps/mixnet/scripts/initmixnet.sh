#!/bin/sh
source ./define.sh

if [[ -e $DOMAIN ]]
then
  echo "$DOMAIN exists"
else
  mkdir $DOMAIN
  mkdir $DOMAIN/policy_keys
  echo "$DOMAIN created"
fi

go install github.com/jlmucb/cloudproxy/go/apps/mixnet...

cp $GOPATH/bin/mixnet_simpleclient /Domains
cp $GOPATH/bin/mixnet_simpleserver /Domains
cp $GOPATH/bin/mixnet_directory /Domains
cp $GOPATH/bin/mixnet_router /Domains
cp $GOPATH/bin/mixnet_proxy /Domains

if [[ -e $TEMPLATE ]]
then
  echo "$TEMPLATE exists"
else
  cp $OLD_TEMPLATE $TEMPLATE
  echo "$OLDTEMPLATE copied to $TEMPLATE"
fi

if [[ -e $DOMAIN/linux_tao_host ]]
then
  echo "$DOMAIN/linux_tao_host exists"
else
  mkdir $DOMAIN/linux_tao_host
  echo "$DOMAIN/linux_tao_host created"
fi

#
# For soft tao, we need a key and it must be in the template.
#

KEY_NAME="$($GOPATH/bin/tao domain newsoft -soft_pass xxx -config_template $TEMPLATE $DOMAIN/linux_tao_host)"
echo "host_name: \"$KEY_NAME\"" | tee -a $TEMPLATE


if [[ -e $DOMAIN ]]
then
  echo "$DOMAIN exists"
else
  mkdir $DOMAIN
  mkdir $DOMAIN/policy_keys
  echo "$DOMAIN created"
fi

progs=( "mixnet_router" "mixnet_proxy" "mixnet_directory" "mixnet_simpleserver" "mixnet_simpleclient" )
for prog in "${progs[@]}";
do
            if [[ -e $DOMAIN/$prog ]]
            then
              echo "$DOMAIN/$prog exists"
              rm $DOMAIN/$progs/*
            else
              mkdir $DOMAIN/$prog
              echo "$DOMAIN/$prog created"
            fi
done
cp $GOPATH/src/github.com/jlmucb/cloudproxy/go/apps/mixnet/*.pem /Domains/domain.mixnet/mixnet_simpleserver

$GOPATH/bin/tao domain init -tao_domain $DOMAIN -config_template $TEMPLATE -pub_domain_address "127.0.0.1" -pass xxx
