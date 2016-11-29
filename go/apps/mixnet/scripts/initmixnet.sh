#!/bin/sh
source ./define.sh

mkdir -p $DOMAINROOT
mkdir -p $DOMAIN

if [[ -e $DOMAIN ]]
then
  echo "$DOMAIN exists"
else
  mkdir $DOMAIN
  mkdir $DOMAIN/policy_keys
  echo "$DOMAIN created"
fi

go install github.com/jlmucb/cloudproxy/go/apps/mixnet...

cp $GOPATH/bin/mixnet_simpleclient $DOMAINROOT
cp $GOPATH/bin/mixnet_simpleserver $DOMAINROOT
cp $GOPATH/bin/mixnet_directory $DOMAINROOT
cp $GOPATH/bin/mixnet_router $DOMAINROOT
cp $GOPATH/bin/mixnet_proxy $DOMAINROOT

cp $OLD_TEMPLATE $TEMPLATE

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

KEY_NAME="$($GOPATH/bin/tao domain newsoft -soft_pass $PASSWORD -config_template $TEMPLATE $DOMAIN/linux_tao_host)"
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
              rm -f $DOMAIN/$progs/*
            else
              mkdir $DOMAIN/$prog
              echo "$DOMAIN/$prog created"
            fi
done
cp $GOPATH/src/github.com/jlmucb/cloudproxy/go/apps/mixnet/*.pem $DOMAIN/mixnet_simpleserver

$GOPATH/bin/tao domain init -tao_domain $DOMAIN -config_template $TEMPLATE -pub_domain_address "127.0.0.1" -pass $PASSWORD
