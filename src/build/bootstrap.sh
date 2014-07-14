#!/bin/bash

# Build ninja and configure the build system.
# Run this script once, before any of the other scripts in this directory.

set -e # quit script on first error

build_dir="$(dirname $0)"
src_dir="${build_dir}/.."

echo "Building ninja"
(cd ${src_dir}/third_party/ninja && ./bootstrap.py)

${build_dir}/config.sh

cat <<END
To build Tao, simply execute:
   ${src_dir}/build.sh
Alternatively, invoke ninja directly using either:
   ${src_dir}/third_party/ninja/ninja -C out/Debug
Or:
   ${src_dir}/third_party/ninja/ninja -C out/Release
END
