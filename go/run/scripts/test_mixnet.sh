#!/bin/bash
# Testing script for driving the development of the mixnet.

set -o nounset
set -o errexit

gowhich() {
	WHICH=$(which which)
	echo -n "$(PATH="${GOPATH//://bin:}/bin" $WHICH "$1")"
}

DOMAIN="/tmp/test_domain"
DOMAIN_PUB="${DOMAIN}.pub"
TYPE="Soft"
FAKE_PASS=BogusPass

# Make sure we have sudo privileges before using them to try to start linux_host
# below.
sudo test true


### Create domain.
echo "----------------- Creating domain."
GUARD="Datalog"
SCRIPT_PATH="$(readlink -e "$(dirname "$0")")"
TEMPLATE="${SCRIPT_PATH}"/domain_template.pb
ADMIN="$(gowhich tao_admin)"
HOST_REL_PATH=linux_tao_host
CA_ADDR="localhost:8124"

TEMP_FILE=`mktemp /tmp/domain_template.XXXXXX`
cat "$TEMPLATE" | sed "s/REPLACE_WITH_DOMAIN_GUARD_TYPE/$GUARD/g" > $TEMP_FILE

"$ADMIN" -operation key -domain_path $DOMAIN -pass $FAKE_PASS \
-config_template "$TEMP_FILE" $HOST_REL_PATH

KEY_NAME=$("$ADMIN" -config_template "$TEMP_FILE" -domain_path $DOMAIN \
-pass $FAKE_PASS -logtostderr $HOST_REL_PATH)

echo host_name: \"$KEY_NAME\" >> $TEMP_FILE

"$ADMIN" -operation domain -domain_path $DOMAIN \
	-config_template $TEMP_FILE -pub_domain_address "$CA_ADDR" \
	-pass $FAKE_PASS -logtostderr

"$ADMIN" -operation policy -add_host -add_programs -add_containers -add_vms \
	-add_linux_host -add_guard -domain_path $DOMAIN -pass $FAKE_PASS \
	-config_template $TEMP_FILE -logtostderr

mkdir -p "${DOMAIN}.pub/${HOST_REL_PATH}"
cp $DOMAIN/$HOST_REL_PATH/{cert,keys} "${DOMAIN_PUB}/${HOST_REL_PATH}"
echo "Temp public domain directory: ${DOMAIN_PUB}"


### Start TaoCA.
echo "----------------- Starting TaoCA"
"$(gowhich tcca)" -config ${DOMAIN}/tao.config -password ${FAKE_PASS} &
CAPID=$!
sleep 2

### Start LinuxHost.
echo "----------------- Starting LinuxHost"
sudo "$(gowhich linux_host)" -config_path ${DOMAIN_PUB}/tao.config \
     -pass ${FAKE_PASS} &
HOSTPID=$!
sleep 2


### Start mixnet router.
echo "----------------- Starting Mixnet Router"
DSPID=$("$(gowhich tao_launch)" -sock ${DOMAIN_PUB}/linux_tao_host/admin_socket \
	"$(gowhich mixnet_router)" -config=${DOMAIN_PUB}/tao.config)


### Start mixnet proxy.
echo "----------------- Starting Mixnet Proxy"
"$(gowhich mixnet_proxy)" -config=${DOMAIN_PUB}/tao.config

echo "Waiting for the tests to finish"
sleep 2

echo "Cleaning up remaining programs"
kill $DSPID
kill $CAPID
sudo kill $HOSTPID
sudo rm -f ${DOMAIN_PUB}/linux_tao_host/admin_socket
