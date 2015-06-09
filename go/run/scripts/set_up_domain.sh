#!/bin/bash

if [ "$#" != "1" ]; then
	echo "Must supply a type of domain guard: 'Datalog', 'ACLs', 'AllowAll', or 'DenyAll'"
	exit 1
fi

set -o nounset
set -o errexit


GUARD=$1
WHICH=$(which which)
ADMIN="$(PATH="${GOPATH//://bin:}/bin" $WHICH tao_admin)"
SCRIPT_PATH="$(readlink -e "$(dirname "$0")")"
TEMPLATE="${SCRIPT_PATH}"/domain_template.pb
DOMAIN_PATH=`mktemp -d /tmp/domain.XXXXXX`
HOST_REL_PATH=linux_tao_host
FAKE_PASS=BogusPass

# Create the linux_host key before creating the domain. This is needed in this
# case so that the host principal is available for the policy. In a real
# deployment, the host principal name is already known before the machine is set
# up, since it is, e.g., the PCRs of the OS, along with the AIK of the TPM.
KEY_NAME=$("$ADMIN" -operation key -domain_path $DOMAIN_PATH -pass $FAKE_PASS \
	-config_template "$TEMPLATE" $HOST_REL_PATH)

# Add the hostname of the key to the template.
TEMP_FILE=`mktemp /tmp/domain_template.XXXXXX`
cat "$TEMPLATE" | sed "s/REPLACE_WITH_DOMAIN_GUARD_TYPE/$GUARD/g" > $TEMP_FILE
echo host_name: \"$KEY_NAME\" >> $TEMP_FILE

# Now create the domain itself.
"$ADMIN" -operation domain -domain_path $DOMAIN_PATH -config_template $TEMP_FILE \
	-pass $FAKE_PASS -logtostderr

# Create the docker images.
"${SCRIPT_PATH}"/build_docker.sh ${DOMAIN_PATH}/policy_keys/cert \
	${DOMAIN_PATH}/tao.config

# Create the linux_host image for use in a VM.
"${SCRIPT_PATH}"/build_linux_host.sh ${DOMAIN_PATH}/policy_keys/cert \
	${DOMAIN_PATH}/tao.config

# Add domain-specific hashes to the policy.
"$ADMIN" -operation policy -add_host -add_programs -add_containers -add_vms \
	-add_linux_host -add_guard -domain_path $DOMAIN_PATH -pass $FAKE_PASS \
	-config_template $TEMP_FILE -logtostderr

rm $TEMP_FILE
echo "Temp domain directory: $DOMAIN_PATH"
