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

# Multi-purpose script for setting up and running tao and cloudproxy tests.
#
# Before using this script, you must have built everything in ROOT/src:
#    cd $ROOT/src && \
#    ./build/bootstrap.sh && \
#    ./third_party/ninja/ninja -C out/Debug
# If you wish to use the TPM, you must have also followed the directions in
# $ROOT/Doc/SetupTPM.txt to take ownership of the TPM.

set -e # quit script on first error

#INSTALL BEGIN
# Note: This section of code is removed by install.sh
test_dir=""
test_ver="Debug"
test_tpm="no"
for arg in "$@"; do
	case "$arg" in
		-Debug|-debug)
			test_ver="Debug"
			;;
		-Release|-release)
			test_ver="Release"
			;;
		-notpm)
			test_tpm="no"
			;;
		-tpm)
			test_tpm="yes"
			;;
		*)
			test_dir="$arg"
			;;
	esac
done
if [ ! "$test_dir" ]; then
	echo "Usage: $0 [options] <dir>"
	echo "  Installs tao testing scripts into <dir>, which will be created"
	echo "  if it does not yet exist."
	echo "Options:"
	echo "  -debug       Use Debug binaries (the default)."
	echo "  -release     Use Release binaries."
	echo "  -notpm       Use a fake TPM (the default)."
	echo "  -tpm         Use the TPM."
	exit 1
fi
if [ -e "$test_dir" -a ! -d "$test_dir" ]; then
	echo "$test_dir: path exists but is not a directory"
	exit 1
fi
mkdir -p "$test_dir"
root_dir="$(dirname $0)"
# canonicalize
root_dir=$(readlink -e "$(dirname $0)/..")
test_dir=$(readlink -e "$test_dir")
echo "Installing tao test scripts into: $test_dir"
# sanity checks
if [ ! -f "$root_dir/src/install.sh" -o ! -d "$test_dir" ]; then
	echo "install failed: could not canonicalize paths"
	exit 1
fi
mkdir -p "$test_dir/scripts"
scripts="setup.sh env.sh start.sh restart.sh monitor.sh test.sh refresh.sh
stop.sh clean.sh hash.sh"
rm -f "$test_dir/scripts/tao.sh"
sed '/^#INSTALL BEGIN/,/^#INSTALL END/d' "$root_dir/src/install.sh" \
			>"$test_dir/scripts/tao.sh"
chmod +x "$test_dir/scripts/tao.sh"
	
cd "$test_dir/scripts/"
perl -p -i -e "s|^export TAO_VERSION=.*\$|export TAO_VERSION="\""$test_ver"\""|" tao.sh
perl -p -i -e "s|^export ROOT=.*\$|export ROOT="\""$root_dir"\""|" tao.sh
perl -p -i -e "s|^export TEST=.*\$|export TEST="\""$test_dir"\""|" tao.sh
perl -p -i -e "s|^export USE_TPM=.*\$|export USE_TPM="\""$test_tpm"\""|" tao.sh
for script in "setup.sh" "env.sh" "start.sh" "restart.sh" "monitor.sh" \
	"test.sh" "refresh.sh" "stop.sh" "clean.sh" "hash.sh" "help.sh"; do
	rm -f $script
	ln -s tao.sh $script
done
cd "$test_dir"
rm -f bin
ln -s $root_dir/src/out/$test_ver/bin bin
mkdir -p logs
cat <<END
Done installing. 
  $test_dir/bin               # Link to out/$test_ver/bin.
  $test_dir/logs              # Log files.
  $test_dir/scripts           # Useful scripts.
Typical next steps:
  cd $test_dir/
  ./scripts/setup.sh          # Create keys, hashes, whitelists, etc.
  ./scripts/start.sh          # Run Tao CA and Linux Tao server.
  ./scripts/test.sh fserver   # Run fserver test.
  ./scripts/stop.sh           # Kill all Tao programs.
  ./scripts/refresh.sh        # Refresh hashes and whitelists.
Run $test_dir/scripts/help.sh for more info."
END
exit 0
#INSTALL END

export TAO_VERSION=undef # replaced with "Debug" or "Release" by install.sh
export ROOT=undef # replaced with path to root dir by install.sh
export TEST=undef # replaced with path to test dir by install.sh
export USE_TPM=undef # replaced with "yes" or "no" by install.sh

export BUILD=${ROOT}/src/out/${TAO_VERSION}/bin
export PASS=cppolicy # policy password

export GLOG_v=2
export GLOG_logtostderr=no
export GLOG_alsologtostderr=no
export GLOG_stderrthreshold=3  # only log FATAL to stderr
export GLOG_log_dir=${TEST}/logs

#export HOSTED_PROGRAMS=$(echo ${BUILD}/*)
HOSTED_PROGRAMS=$(echo ${BUILD}/{client,server,fclient,fserver})
HOSTED_PROGRAMS=$HOSTED_PROGRAMS,${BUILD}/http_echo_server
HOSTED_PROGRAMS=$HOSTED_PROGRAMS,${BUILD}/https_echo_server
TAO_PROGRAMS=$(cd $TEST/bin; echo * | grep -v '\.a$')

WATCHFILES="bin/tcca bin/linux_tao_service whitelist tao.config"

# log a to stderr for admin stuff, otherwise it is really quiet
ADMIN_ARGS="-config_path tao.config -policy_pass $PASS -alsologtostderr=1"
admin="bin/tao_admin $ADMIN_ARGS"
start_hosted="bin/start_hosted_program -program"

cd $TEST

# return at most the first 15 chars of argument
# suitable for pgrep -x or pkill -x
# e.g. shortname long_binary_filename ==> long_binary_fil
function shortname()
{
	name="$1"
	echo "\<${name:0:15}\>"
}

function showenv()
{
	echo "# Tao/CloudProxy environment variables"
	echo export ROOT=\"$ROOT\"
	echo export BUILD=\"$BUILD\"
	echo export TEST=\"$TEST\"
	echo export PASS=\"$PASS\"
	echo export GLOG_v=\"$GLOG_v\"
	echo export GLOG_logtostderr=\"$GLOG_logtostderr\"
	echo export GLOG_alsologtostderr=\"$GLOG_alsologtostderr\"
	echo export GLOG_stderrthreshold=\"$GLOG_stderrthreshold\"
	echo export GLOG_log_dir=\"$GLOG_log_dir\"
	echo export HOSTED_PROGRAMS=\"$HOSTED_PROGRAMS\"
}

function cleanup()
{
	rm -f ${TEST}/logs/*
	rm -rf ${TEST}/{*keys,tpm,fake_tpm,whitelist,tao.config,acls_sig}
	echo "Cleared all Tao configuration data"
}

function stoptests()
{
	killed=0
	for prog in $TAO_PROGRAMS; do
		if pgrep -lx `shortname "$prog"`; then
			pkill -x `shortname "$prog"`
			killed=1
		fi
	done
	if [ $killed -eq 1 ]; then
		sleep 1
		echo "Killed all Tao services and processes"
	else
		echo "No running Tao services or processes"
	fi
	rm -f _linux_tao_socket _start_hosted_program_socket _linux_tao_stop_socket
}

function setup()
{
	rm -f bin
	ln -s ${BUILD} bin
	mkdir -p logs

	$admin -init ${ROOT}/run/tao-default.config -name testing 
	if [ "$USE_TPM" == "yes" ]; then
		echo "Creating and attesting a new TPM AIK."
		mkdir -p tpm
		bin/make_aik -alsologtostderr=1 --aik_blob_file tpm/aikblob
		bin/attest_to_aik $ADMIN_ARGS --aik_blob_file tpm/aikblob \
			--aik_attest_file tpm/aik.attest
		PCRS=`bin/get_pcrs`
	    $admin -whitelist "${PCRS}:PCR_SHA1:Linux"
	else
		echo "Creating and attesting a new fake TPM key."
		$admin -make_fake_tpm fake_tpm
		$admin -whitelist "FAKE_TPM:FAKE_HASH:BogusTPM"
		# fixme: this should be FAKE_HASH, not SHA256, but the channels
		# don't yet support hash_alg parameter
		$admin -whitelist "FAKE_PCRS:SHA256:Linux"
	fi
	$admin -whitelist ${HOSTED_PROGRAMS// /,}
	$admin -newusers tmroeder,jlm
	$admin -signacl ${ROOT}/run/acls.ascii -acl_sig_path acls_sig
	mkdir -p file_client_files
	mkdir -p file_server_files
	mkdir -p file_server_meta
	echo "Tao configuration is ready"
}

function refresh()
{
	$admin -refresh -whitelist ${HOSTED_PROGRAMS// /,}
}

function startsvcs()
{
	if pgrep -x `shortname tcca` >/dev/null; then
		echo "TCCA service already running";
	else
		bin/tcca $ADMIN_ARGS &
		sleep 1
		echo "TCCA service now running"
	fi

	if pgrep -x `shortname linux_tao_service` >/dev/null; then
		echo "LinuxTao service already running";
	else
		if [ "$USE_TPM" == "yes" ]; then
			bin/linux_tao_service &
		else
			bin/linux_tao_service -nouse_tpm &
		fi
		sleep 1
		echo "LinuxTao service now running"
	fi
}

function monitor()
{
	echo "Monitoring Tao files..."
	while true; do
		inotifywait -e modify -e delete -e attrib $WATCHFILES >/dev/null 2>&1
		echo "Files have changed, waiting for quiet..."
		sleep 1
		while inotifywait -t 3 -e modify -e delete -e attrib $WATCHFILES >/dev/null 2>&1; do
			echo "Still waiting for quiet..."
			sleep 1
		done
		echo "Restarting Tao services..."
		refresh
		stoptests
		startsvcs
	done
}

function gethash()
{
	cat "$1" | sha256sum | cut -d' ' -f1 | xxd -r -ps | base64 | tr '/+' '_-' | tr -d '=' 
}

function testpgm()
{
	case "$1" in
		client|server)
			echo "Starting cloudproxy server..."
			server_pid=`$start_hosted bin/server -- --v=2`
			sleep 2
			tail -f $GLOG_log_dir/server.INFO &
			server_tail_pid=$!
			echo "Starting cloudproxy client..."
			client_pid=`$start_hosted  bin/client -- --v=2`
			sleep 2
			tail -f $GLOG_log_dir/client.INFO &
			client_tail_pid=$!
			sleep 2
			echo "Killing cloudproxy server and client..."
			kill $server_pid $client_pid 2>/dev/null
			sleep 2
			kill $server_tail_pid $client_tail_pid 2>/dev/null
			;;
		file|fclient|fserver)
			echo "Clean cloudproxy file server data..."
			rm -f file_server_files/* file_server_meta/* file_client_files/*
			# make some test data too
			echo "test data $RANDOM" >> file_client_files/test
			echo "Starting cloudproxy file server..."
			server_pid=`$start_hosted  bin/fserver -- --v=2`
			sleep 2
			tail -f $GLOG_log_dir/fserver.INFO &
			server_tail_pid=$!
			echo "Starting cloudproxy file client..."
			client_pid=`$start_hosted  bin/fclient -- --v=2`
			sleep 2
			tail -f $GLOG_log_dir/fclient.INFO &
			client_tail_pid=$!
			sleep 2
			echo "Killing cloudproxy file server and client..."
			kill $server_pid $client_pid 2>/dev/null
			sleep 2
			kill $server_tail_pid $client_tail_pid 2>/dev/null
			;;
		http)
			echo "Starting cloudproxy http echo server..."
			server_pid=`$start_hosted  bin/http_echo_server -- --v=2`
			sleep 2
			tail -f $GLOG_log_dir/http_echo_server.INFO &
			tail_pid=$!
			sleep 1
			read -p "Press enter to kill http echo server..."
			echo "Killing cloudproxy http echo server..."
			kill $server_pid 2>/dev/null
			sleep 2
			kill $tail_pid 2>/dev/null
			;;
		https)
			echo "Starting cloudproxy https echo server..."
			server_pid=`$start_hosted  bin/https_echo_server -- --v=2`
			sleep 2
			tail -f $GLOG_log_dir/https_echo_server.INFO &
			tail_pid=$!
			sleep 1
			read -p "Press enter to kill https echo server..."
			echo "Killing cloudproxy https echo server..."
			kill $server_pid 2>/dev/null
			sleep 2
			kill $tail_pid 2>/dev/null
			;;
		tao)
			echo "Running tao unit tests..."
			bin/tao_test -program bin/protoc \
				--gtest_filter=-TPM*:KvmVmFactory*
			;;
		cloudproxy)
			echo "Running cloudproxy unit tests..."
			bin/cloudproxy_test
			;;
		unit|unittest)
			echo "Running tao and cloudproxy unit tests..."
			bin/tao_test -program bin/protoc \
				--gtest_filter=-TPM*:KvmVmFactory* \
				&& bin/cloudproxy_test
			;;
		help|*)
			echo "Available test programs:"
			echo "  server      # cloud client/server test"
			echo "  fserver     # file client/server test"
			echo "  http        # http echo test"
			echo "  https       # https echo test"
			echo "  tao         # tao unit tests"
			echo "  cloudproxy  # tao unit tests"
			echo "  unit        # tao and cloudproxy unit tests"
			;;
	esac
}

case "$(basename $0)" in
	setup.sh)
		stoptests
		cleanup
		setup
		;;
	env.sh)
		showenv
		;;
	start.sh)
		startsvcs
		;;
	restart.sh)
		stoptests
		startsvcs
		;;
	monitor.sh)
		monitor
		;;
	test.sh)
		#refresh
		#startsvcs
		if [ "$#" == "0" ]; then
			testpgm help
		else
			for f in "$@"; do
				testpgm $f
			done
		fi
		;;
	refresh.sh)
		refresh
		;;
	stop.sh)
		stoptests
		;;
	clean.sh)
		stoptests
		cleanup
		;;
	hash.sh)
		for f in "$@"; do
			gethash $f
		done
		;;
	help|*)
		cat <<END
Scripts in $TEST/scripts:
  setup.sh           # Re-initialize all keys, whitelists, configuration, etc.
  env.sh             # Show environment variables.
  start.sh           # Start Tao services.
  restart.sh         # Restart Tao services.
  monitor.sh         # Watch binaries and restart Tao services as needed.
  test.sh <prog>     # Run tests for <prog>. Use prog "help" for choices.
  refresh.sh         # Refresh hashes and whitelists, but keep existing keys.
  stop.sh            # Kill processes, remove logs.
  clean.sh           # Remove all keys, configuration, logs, etc.
  hash.sh [file...]  # Hash files; use - for stdin.
END
		exit 0
		;;
esac

