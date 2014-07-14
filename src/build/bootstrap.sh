#!/bin/bash

# run this program from fileProxy/src as build/bootstrap.sh

set -e # quit script on first error

build_dir="$(dirname $0)"
src_dir="${build_dir}/.."

echo Building ninja
(cd ${src_dir}/third_party/ninja && ./bootstrap.py)

echo Configuring ninja build files using cmake for Debug and Release build
mkdir -p ${src_dir}/out/Debug
(cd ${src_dir}/out/Debug && cmake -DCMAKE_BUILD_TYPE=Debug -G Ninja ../..)
mkdir -p ${src_dir}/out/Release
(cd ${src_dir}/out/Release && cmake -DCMAKE_BUILD_TYPE=Release -G Ninja ../..)

cat <<END
To build Tao, add this directory to your PATH:
   ${src_dir}/third_party/ninja/
Then, from within ${src_dir}, execute either:
   ninja -C out/Debug
Or:
   ninja -C out/Release
END
