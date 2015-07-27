#!/bin/bash

if [ "$#" -lt "2" ]; then
	echo "Must supply a type of domain guard ('Datalog', 'ACLs', 'AllowAll',"
	echo "or 'DenyAll') and a root Tao type ('TPM' or 'Soft')."
	exit 1
fi

set -o nounset
set -o errexit

GUARD="$1"
TYPE="$2"
if [ "$#" == "3" ]; then
	CA_ADDR="$3"
else
	CA_ADDR=""
fi

WHICH=$(which which)
ADMIN="$(PATH="${GOPATH//://bin:}/bin" $WHICH tao_admin)"
SCRIPT_PATH="$(readlink -e "$(dirname "$0")")"
TEMPLATE="${SCRIPT_PATH}"/domain_template.pb
DOMAIN_PATH=$(mktemp -d /tmp/domain.XXXXXX)
HOST_REL_PATH=linux_tao_host

# Used to encrypt policy keys (as well as the keys for SoftTao) on disk.
FAKE_PASS=BogusPass

if [ "$TYPE" == "TPM" ]; then
  # TPMTao: need sudo to read from /dev/tpm0.
	sudo test true

  # Find the aikblob file in cwd or one of our parents
  path="."
  while [ "$path" != "/" ]; do
    if [ -e "$path/aikblob" ]; then
      break
    fi
    path="$(readlink -f $path/..)"
  done
  if [ ! -e "$path/aikblob" ]; then
	  echo "There must be an aikblob file in or above the current directory."
    exit 1
  fi
  aikpath="$path/aikblob"
fi

# Fill in guard type in the domain template.
TEMP_FILE=`mktemp /tmp/domain_template.XXXXXX`
cat "$TEMPLATE" | sed "s/REPLACE_WITH_DOMAIN_GUARD_TYPE/$GUARD/g" > $TEMP_FILE

# SoftTao: generate root keys for signing, attestation, and sealing.
if [ "$TYPE" == "Soft" ]; then
	"$ADMIN" -operation key -domain_path $DOMAIN_PATH -pass $FAKE_PASS \
		-config_template "$TEMP_FILE" $HOST_REL_PATH

	# Get key host name and add it to the template.
	KEY_NAME=$("$ADMIN" -config_template "$TEMP_FILE" -domain_path $DOMAIN_PATH \
		-pass $FAKE_PASS -logtostderr $HOST_REL_PATH)

	# Specify key principal as host name.
	echo host_name: \"$KEY_NAME\" >> $TEMP_FILE
fi

# Now create the domain itself. This generates a configuration file and a
# private/public key pair in policy_keys/{signer,cert}, the activity
# owner's root key.
"$ADMIN" -operation domain -domain_path $DOMAIN_PATH \
	-config_template $TEMP_FILE -pub_domain_address "$CA_ADDR" \
	-pass $FAKE_PASS -logtostderr

# Create the docker images.
"${SCRIPT_PATH}"/build_docker.sh ${DOMAIN_PATH}

# Create the linux_host image for use in a VM.
"${SCRIPT_PATH}"/build_linux_host.sh ${DOMAIN_PATH}

# Add domain-specific hashes to the policy (e.g. linux_host, demo_client,
# and demo_server).
"$ADMIN" -operation policy -add_host -add_programs -add_containers -add_vms \
	-add_linux_host -add_guard -domain_path $DOMAIN_PATH -pass $FAKE_PASS \
	-config_template $TEMP_FILE -logtostderr

# TPMTao: add TPM principal to domain, if one exists.
if [ "$TYPE" == "TPM" ]; then
	sudo "$ADMIN" -operation policy -add_tpm -principal tpm \
		  -pass $FAKE_PASS -domain_path $DOMAIN_PATH \
		  -config_template $TEMP_FILE -logtostderr
  cp "$aikpath" ${DOMAIN_PATH}/aikblob
fi

rm $TEMP_FILE
echo "Temp domain directory: $DOMAIN_PATH"

# If we're using a soft Tao, and a public Tao domain was created, we need to
# copy the root signing key and certificate.
if [ "$#" == "3" ] && [ "$TYPE" == "Soft" ]; then
	mkdir -p "${DOMAIN_PATH}.pub/${HOST_REL_PATH}"
	cp $DOMAIN_PATH/$HOST_REL_PATH/{cert,keys} "${DOMAIN_PATH}.pub/${HOST_REL_PATH}"
	echo "Temp public domain directory: ${DOMAIN_PATH}.pub"
fi
