#!/bin/bash

set -o nounset
set -o errexit

# This script assumes that the code for running the demo server and demo client
# has already been built in standalone mode using build_standalone.
if [ "$#" != "1" ]; then
	echo "Must supply the path to an initialized domain."
	exit 1
fi

# arguments: build_docker <script path> <local relative app path> <policy cert # path> <tao.config path>
# e.g., build_docker $0 demo_server $1 $2
function build_docker() {
	# This script currently only supports Linux (or any system that has a working
	# readlink -e)

	script_name="$1"
	app_name="$2"
	policy_cert="$3"
	tao_config="$4"

	DEMO_DIR="$(readlink -e "$(dirname "$script_name")")"/../../apps/demo
  TEMP_DIR=$(mktemp -d)
	cp "${DEMO_DIR}"/${app_name}/Dockerfile ${TEMP_DIR}/Dockerfile
	mkdir ${TEMP_DIR}/tmp
	mkdir ${TEMP_DIR}/bin
	WHICH=$(which which)
	APP_BIN="$(PATH="${GOPATH//://bin:}/bin" $WHICH ${app_name})"
	cp "$APP_BIN" ${TEMP_DIR}/bin/${app_name}
	mkdir ${TEMP_DIR}/policy_keys
	cp $policy_cert ${TEMP_DIR}/policy_keys/cert
	cp $tao_config ${TEMP_DIR}/tao.config

  tar -C ${TEMP_DIR} -czf "$APP_BIN".img.tgz $(ls ${TEMP_DIR})
  rm -rf ${TEMP_DIR}
}

build_docker "$0" demo_server "$1/policy_keys/cert" "$1/tao.config"
build_docker "$0" demo_client "$1/policy_keys/cert" "$1/tao.config"
