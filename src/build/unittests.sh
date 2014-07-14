#!/bin/bash
# Copyright (c) 2014, Kevin Walsh. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Helper for running unit tests.

set -e # quit script on first error

root_dir=$(readlink -e "$(dirname $0)/../..")

stderrthreshold=3
verbose=0

test_ver="Debug"
for arg in "$@"; do
	case "$arg" in
		-Debug|-debug)
			test_ver="Debug"
			shift
			;;
		-Release|-release)
			test_ver="Release"
			shift
			;;
		-v)
			verbose=$((verbose+1))
			stderrthreshold=0
			shift;
			;;
		-*)
			echo "Huh? $arg"
			exit 1
			;;
	esac
done

# Do everything in a temp directory or somewhere else safe
#tempdir=`mktemp -d`
tempdir=~/unittest

mkdir -p $tempdir
cd $tempdir
rm -rf ./logs
mkdir -p ./logs
echo "Unit test working directory: $tempdir"

# Set some variables
export GLOG_v=${verbose}
export GLOG_log_dir=./logs
export GLOG_stderrthreshold=${stderrthreshold}
bin=${root_dir}/src/out/${test_ver}/bin
tpm=${root_dir}/tpm

# Make sure we have an AIK for TPM testing
if [ ! -f "$tpm/aikblob" ]; then
	rm -rf $tpm
	$bin/tpm_tao -path $tpm -create
fi

errors=0

# Run individual unit tests
if ! $bin/tao_test --aik_blob_file $tpm/aikblob -- --gtest_filter=*; then
	errors=$((errors+1))
fi
# if ! $bin/cloudproxy_test -- --gtest_filter=*; then
# 	errors=$((errors+1))
# fi

# Run an end-to-end unit test
green="[32m"
red="[31m"
reset="[0m"
echo
echo "${green}[----------]${reset} 1 End-to-end Tao unit test"
for guard in "acls" "datalog"; do
	echo "${green}[ RUN      ]${reset} Run demo, with guard = $guard"
	if (
		${root_dir}/src/install.sh -q -${guard} -${test_ver} .
		./scripts/setup.sh
		./scripts/start.sh
		sleep 0.25
		./scripts/host.sh bin/demo
		./scripts/stop.sh
	) > ./logs/end-to-end.msgs 2>&1; then
		echo "${green}[       OK ]${reset} Run demo, with guard = $guard"
	else
		echo "${red}[     FAIL ]${reset} Run demo, with guard = $guard"
		errors=$((errors+1))
	fi
done
echo "${green}[----------]${reset} 1 End-to-end Tao unit test"

echo
if [ $errors -ne 0 ]; then
	echo "${red}Some unit tests failed${reset}"
else
	echo "${green}All unit tests passed${reset}"
fi
