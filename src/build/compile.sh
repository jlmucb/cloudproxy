#!/bin/bash

# Compile CloudProxy.
# Run this script to compile all code. You should have already run boostrap.sh
# (and possibly also config.sh, if you subsequently changed any cmake
# configuration files).

set -e # quit script on first error

build_dir="$(dirname $0)"
src_dir="${build_dir}/.."

ver="Debug"
if [ $# -eq 1 -a "$1" == "Debug" ]; then
	ver="Debug"
elif [ $# -eq 1 -a "$1" == "Release" ]; then
	ver="Release"
elif [ $# -ne 0 ]; then
	echo "Unrecognized options: $@"
	exit 1
fi

echo "Compiling CloudProxy $ver target"

${src_dir}/third_party/ninja/ninja -C out/$ver

