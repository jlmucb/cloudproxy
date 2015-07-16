#!/bin/bash

set -o errexit
set -o nounset

# Download the latest stable version of the CoreOS image and script to the
# current directory.
curl -G http://stable.release.core-os.net/amd64-usr/current/coreos_production_qemu_image.img.bz2 > coreos_production_qemu_image.img.bz2
curl -G http://stable.release.core-os.net/amd64-usr/current/coreos_production_qemu_image.img.bz2.sig > coreos_production_qemu_image.img.bz2.sig

SCRIPT_PATH="$(readlink -e "$(dirname "$0")")"
TEMP_FILE=$(mktemp -d /tmp/gnupg.XXXXXX)
chmod 700 "${TEMP_FILE}"

echo "Verifying the image signature."
gpg --homedir "${TEMP_FILE}" --batch --import "${SCRIPT_PATH}"/coreos.pk 
if ! gpg --homedir "${TEMP_FILE}" --trust-model always \
	--verify coreos_production_qemu_image.img.bz2.sig \
	coreos_production_qemu_image.img.bz2; then
	echo "ERROR: the CoreOS image fails signature verification! "
	echo "Do not use this image!"
	exit 1
fi

echo "Unzipping the image."
bunzip2 coreos_production_qemu_image.img.bz2

echo "Now make sure the domain template points to this image."
echo "Also make sure you have an authorized keys file with a key you control, "
echo "and set up ssh-agent with this key."
