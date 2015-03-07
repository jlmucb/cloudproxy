#!/bin/bash

set -o nounset
set -o errexit

ADMIN=${GOPATH}/bin/tao_admin
SCRIPT_PATH=$(readlink -e $(dirname $0))
TEMPLATE=${SCRIPT_PATH}/domain_datalog_template.pb
DOMAIN_PATH=${SCRIPT_PATH}/domain
HOST_REL_PATH=linux_tao_host
FAKE_PASS=BogusPass

# Create the linux_host key before creating the domain. This is needed in this
# case so that the host principal is available for the policy. In a real
# deployment, the host principal name is already known before the machine is set
# up, since it is, e.g., the PCRs of the OS, along with the AIK of the TPM.
KEY_NAME=$($ADMIN -operation key -domain_path $DOMAIN_PATH -pass $FAKE_PASS -config_template $TEMPLATE $HOST_REL_PATH)
echo Got key ${KEY_NAME}

# Add the hostname of the key to the template.
TEMP_FILE=`mktemp /tmp/domain_template.XXXXXX`
cat $TEMPLATE > $TEMP_FILE
echo host_name: \"$KEY_NAME\" >> $TEMP_FILE

# Now create the domain itself.
$ADMIN -operation domain -domain_path $DOMAIN_PATH -config_template $TEMP_FILE -pass $FAKE_PASS -logtostderr

# Add the trusted key host to the rules
$ADMIN -operation policy -domain_path $DOMAIN_PATH -add "TrustedHost($KEY_NAME)" -pass $FAKE_PASS

rm $TEMP_FILE
