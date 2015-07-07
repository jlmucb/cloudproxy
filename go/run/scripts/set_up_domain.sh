#!/bin/bash

if [ "$#" != "2" ]; then
	echo "Must supply a type of domain guard ('Datalog', 'ACLs', 'AllowAll',"
	echo "or 'DenyAll') and a root Tao type ('TPM' or 'Soft')."
	exit 1
fi

set -o nounset
set -o errexit

GUARD="$1"
TYPE="$2"
WHICH=$(which which)
ADMIN="$(PATH="${GOPATH//://bin:}/bin" $WHICH tao_admin)"
SCRIPT_PATH="$(readlink -e "$(dirname "$0")")"
TEMPLATE="${SCRIPT_PATH}"/domain_template.pb
DOMAIN_PATH=$(mktemp -d /tmp/domain.XXXXXX)
HOST_REL_PATH=linux_tao_host

# TPM parameters.
# TODO(tmroeder) move these to domain template.
TPM="/dev/tpm0"
PCRS="17,18" # PCR registers of TPM
AIKBLOB="${HOME}/aikblob"

# Used to encrypt policy keys (as well as the keys for SoftTao) on disk.
FAKE_PASS=BogusPass

# TPMTao: need sudo to read from /dev/tpm0.
if [ "$TYPE" == "TPM" ]; then
	sudo test true
fi

# Fill in guard type in the domain template.
TEMP_FILE=`mktemp /tmp/domain_template.XXXXXX`
cat "$TEMPLATE" | sed "s/REPLACE_WITH_DOMAIN_GUARD_TYPE/$GUARD/g" > $TEMP_FILE

# SoftTao: generate root keys for signing, attestation, and sealing.
if [ "$TYPE" == "Soft" ]; then
	"$ADMIN" -operation key -domain_path $DOMAIN_PATH -pass $FAKE_PASS \
		-config_template "$TEMPLATE" $HOST_REL_PATH

	# Get key host name and add it to the template.
	KEY_NAME=$("$ADMIN" -config_template "$TEMPLATE" -domain_path $DOMAIN_PATH \
		-pass $FAKE_PASS -logtostderr $HOST_REL_PATH)

	# Specify key principal as host name.
	echo host_name: \"$KEY_NAME\" >> $TEMP_FILE
fi

# Now create the domain itself. This generates a configuration file and a
# private/public key pair in policy_keys/{signer,cert}, the activity
# owner's root key.
"$ADMIN" -operation domain -domain_path $DOMAIN_PATH \
	-config_template $TEMP_FILE \
	-pass $FAKE_PASS -logtostderr

# Create the docker images.
"${SCRIPT_PATH}"/build_docker.sh ${DOMAIN_PATH}/policy_keys/cert \
	${DOMAIN_PATH}/tao.config

# Create the linux_host image for use in a VM.
"${SCRIPT_PATH}"/build_linux_host.sh ${DOMAIN_PATH}/policy_keys/cert \
	${DOMAIN_PATH}/tao.config

# Add domain-specific hashes to the policy (e.g. linux_host, demo_client,
# and demo_server).
"$ADMIN" -operation policy -add_host -add_programs -add_containers -add_vms \
	-add_linux_host -add_guard -domain_path $DOMAIN_PATH -pass $FAKE_PASS \
	-config_template $TEMP_FILE -logtostderr

# TPMTao: add TPM principal to domain, if one exists.
if [ "$TYPE" == "TPM" ]; then
	if [ -f "$AIKBLOB" ] && [ -e "$TPM" ]; then
	  	sudo "$ADMIN" -operation policy -add_tpm \
			  -principal tpm -tpm $TPM -pcrs $PCRS -aikblob $AIKBLOB \
			  -pass $FAKE_PASS -domain_path $DOMAIN_PATH \
			  -config_template $TEMP_FILE -logtostderr
	else
		echo "Couldn't add TPM: missing AIK blob '$AIKBLOB' or TPM device"
		echo "'$TPM' not found."
	fi
fi

rm $TEMP_FILE
echo "Temp domain directory: $DOMAIN_PATH"
