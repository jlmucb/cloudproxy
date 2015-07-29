#!/bin/bash

set -o nounset
set -o errexit

if [ "$#" == "2" ]; then
  GUARD="$1"
  TYPE="$2"
  CA_ADDR=""
elif [ "$#" == "3" ]; then
  GUARD="$1"
  TYPE="$2"
  CA_ADDR="$3"
else
	echo "Must supply type of domain guard ('Datalog', 'ACLs', 'AllowAll', or 'DenyAll'),"
	echo "root Tao type ('TPM' or 'Soft'). Optionally, also provide a CA address."
	exit 1
fi

gowhich() {
  WHICH=$(which which)
  echo -n "$(PATH="${GOPATH//://bin:}/bin" $WHICH "$1")"
}

TAO="$(gowhich tao)"
SCRIPT_PATH="$(readlink -e "$(dirname "$0")")"
TEMPLATE_SRC="${SCRIPT_PATH}"/domain_template.pb
DOMAIN=$(mktemp -d /tmp/domain.XXXXXX)
TEMPLATE=$(mktemp /tmp/domain_template.XXXXXX)

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
  AIK_PATH="$path/aikblob"
fi

# Fill in guard type in the domain template.
sed "s/REPLACE_WITH_DOMAIN_GUARD_TYPE/$GUARD/g" "$TEMPLATE_SRC" > $TEMPLATE

# SoftTao: generate root keys for signing, attestation, and sealing.
if [ "$TYPE" == "Soft" ]; then
  KEY_NAME=$("$TAO" domain newsoft -soft_pass $FAKE_PASS \
    -config_template $TEMPLATE $DOMAIN/linux_tao_host)
  KEY_NAME=$(echo -n "$KEY_NAME") # Remove newline

  # Specify key principal as host name.
  echo host_name: \"$KEY_NAME\" >> $TEMPLATE
fi

# Now create the domain itself. This generates a configuration file and a
# private/public key pair in policy_keys/{signer,cert}, the activity
# owner's root key.
"$TAO" domain init -tao_domain $DOMAIN \
  -config_template $TEMPLATE -pub_domain_address "$CA_ADDR" \
  -pass $FAKE_PASS

# Also initialize a default linux host
if [ "$TYPE" == "Soft" ]; then
  "$TAO" host init -tao_domain $DOMAIN -hosting process -root -pass $FAKE_PASS
else
  "$TAO" host init -tao_domain $DOMAIN -hosting process -stacked -parent_type tpm 
fi

# Create the docker images.
"${SCRIPT_PATH}/build_docker.sh" $DOMAIN

# Create the linux_host image for use in a VM.
"${SCRIPT_PATH}/build_linux_host.sh" $DOMAIN

# Add domain-specific hashes to the policy (e.g. linux_host, demo_client,
# and demo_server).
"$TAO" domain policy -add_host -add_programs -add_containers -add_vms \
  -add_linux_host -add_guard -tao_domain $DOMAIN -pass $FAKE_PASS \
  -config_template $TEMPLATE

# TPMTao: add TPM principal to domain, if one exists.
if [ "$TYPE" == "TPM" ]; then
  sudo "$TAO" domain policy -add_tpm \
    -pass $FAKE_PASS -tao_domain $DOMAIN -config_template $TEMPLATE
  cp "$AIK_PATH" ${DOMAIN}/aikblob
fi

rm $TEMPLATE

# If we're using a soft Tao, and a public Tao domain was created, we need to
# copy the root signing key and certificate.
if [ "$#" == "3" ] && [ "$TYPE" == "Soft" ]; then
  mkdir -p "${DOMAIN}.pub/${HOST_REL_PATH}"
  cp $DOMAIN/$HOST_REL_PATH/{cert,keys} "${DOMAIN}.pub/${HOST_REL_PATH}"
  echo "Temp public domain directory: ${DOMAIN}.pub"
fi

echo "Tao domain created in $DOMAIN"
echo "To use this as the default for tao commands, use:"
echo "  export TAO_DOMAIN=$DOMAIN"

