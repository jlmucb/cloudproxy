#!/bin/bash

# Configure the build system.
# You should run this script before running compile.sh if you change any of the
# cmake configuration files.

set -e # quit script on first error

build_dir="$(dirname $0)"
src_dir="${build_dir}/.."

echo "Configuring ninja build files using cmake for Debug and Release build"

mkdir -p ${src_dir}/out/Debug
(cd ${src_dir}/out/Debug && cmake -DCMAKE_BUILD_TYPE=Debug -G Ninja ../..)

mkdir -p ${src_dir}/out/Release
(cd ${src_dir}/out/Release && cmake -DCMAKE_BUILD_TYPE=Release -G Ninja ../..)

