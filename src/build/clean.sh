#!/bin/bash

# Remove CloudProxy compiled files and configuration.
# You must re-run config.sh before compiling again.

set -e # quit script on first error

build_dir="$(dirname $0)"
src_dir="${build_dir}/.."

rm -rf ${src_dir}/out
