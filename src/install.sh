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
# Before using this script, you must have built everything in $TAO_ROOT/src:
#    cd $TAO_ROOT/src && \
#    ./build/bootstrap.sh && \
#    ./third_party/ninja/ninja -C out/Debug
# If you wish to use the TPM, you must have also followed the directions in
# $TAO_ROOT/Doc/SetupTPM.txt to take ownership of the TPM.

set -e # quit script on first error

#INSTALL BEGIN
# Note: This section of code is removed by install.sh
test_dir=""
test_ver="Debug"
test_tpm="no"
verbose="yes"
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
		-notpm)
			test_tpm="no"
			shift
			;;
		-tpm)
			test_tpm="yes"
			shift
			;;
		-q)
			verbose="no"
			shift
			;;
		-*)
			echo "Huh? $arg"
			exit 1
			;;
	esac
done
if [ $# -eq 1 ]; then
	test_dir="$1"
fi
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
if [ "$verbose" == "yes" ]; then
	echo "Installing tao test scripts into: $test_dir"
fi
# sanity checks
if [ ! -f "$root_dir/src/install.sh" -o ! -d "$test_dir" ]; then
	echo "install failed: could not canonicalize paths"
	exit 1
fi
mkdir -p "$test_dir/scripts"
scripts="setup.sh start.sh restart.sh monitor.sh test.sh refresh.sh
stop.sh clean.sh hash.sh"
rm -f "$test_dir/scripts/tao.sh"
sed '/^#INSTALL BEGIN/,/^#INSTALL END/d' "$root_dir/src/install.sh" \
			>"$test_dir/scripts/tao.sh"
chmod +x "$test_dir/scripts/tao.sh"
	
cd "$test_dir/scripts/"
perl -p -i -e "s|^export TAO_TEST=.*\$|export TAO_TEST="\""$test_dir"\""|" tao.sh
for script in "setup.sh" "start.sh" "restart.sh" "monitor.sh" \
	"test.sh" "refresh.sh" "stop.sh" "clean.sh" "hash.sh" "help.sh"; do
	rm -f $script
	ln -s tao.sh $script
done
cd "$test_dir"
rm -f bin
ln -s $root_dir/src/out/$test_ver/bin bin
mkdir -p logs

cat <<END > "$test_dir/tao.env"
# Tao/CloudProxy environment variables"
# export TAO_TEST="$test_dir" # Hardcoded into $test_dir/scripts/*.sh

export TAO_ROOT="$root_dir"
export TAO_VERSION="$test_ver"
export TAO_USE_TPM="$test_tpm"
export TAO_BUILD="\${TAO_ROOT}/src/out/\${TAO_VERSION}/bin"
export TAO_PASS="BogusPass"
export TAO_TPM_PCRS="17, 18"
export GLOG_v=2
export GLOG_logtostderr="no"
export GLOG_alsologtostderr="no"
export GLOG_stderrthreshold=3 # Only log FATAL to stderr.
export GLOG_log_dir="\${TAO_TEST}/logs"

export TAO_HOSTED_PROGRAMS="
\${TAO_BUILD}/client 
\${TAO_BUILD}/server 
\${TAO_BUILD}/fclient 
\${TAO_BUILD}/fserver 
\${TAO_BUILD}/http_echo_server 
\${TAO_BUILD}/https_echo_server 
"

export GOOGLE_HOST_TAO="" # Use $test_dir/scripts/setup.sh to make this.
END

if [ "$verbose" == "yes" ]; then
	cat <<END
Done installing. 
  $test_dir/bin               # Link to out/$test_ver/bin.
  $test_dir/logs              # Log files.
  $test_dir/scripts           # Useful scripts.
  $test_dir/tao.env           # Environment variables.
Typical next steps:
  cd $test_dir/
  ./scripts/setup.sh          # Create keys, hashes, ACLs, etc.
  ./scripts/start.sh          # Run Tao CA and Linux Tao server.
  ./scripts/test.sh fserver   # Run fserver test.
  ./scripts/stop.sh           # Kill all Tao programs.
  ./scripts/refresh.sh        # Refresh hashes, ACLs, etc.
Run $test_dir/scripts/help.sh for more info.
END
fi

exit 0
#INSTALL END

export TAO_TEST=undef # replaced with path to test dir by install.sh
source $TAO_TEST/tao.env

TAO_PROGRAMS=$(cd $TAO_TEST/bin; echo * | grep -v '\.a$')

WATCHFILES="bin/tcca bin/linux_tao domain_acls tao.config tao.env"

# log a to stderr for admin stuff, otherwise it is really quiet
admin_args="-config_path tao.config -policy_pass $TAO_PASS -alsologtostderr=1"
admin="bin/tao_admin $admin_args"
start_hosted="bin/start_hosted_program -program"
tpm_tao="bin/tpm_tao -alsologtostderr=1"
soft_tao="bin/soft_tao -alsologtostderr=1"

function extract_pid()
{
	childname="$1"
	pid=`echo "$childname" | sed 's/^Success: Program([0-9]\+, ".*", ".*", ".*")::PID(\([0-9]\+\))$/\1/'`
	echo "$pid"
}

cd $TAO_TEST

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
	cat tao.env
}

function cleanup()
{
	rm -f ${TAO_TEST}/logs/*
	rm -rf ${TAO_TEST}/{*keys,tpm,fake_tpm,whitelist,tao.config,acls_sig}
	echo "Cleared all Tao configuration data"
}

function stoptests()
{
	echo "Attempting graceful shutdown..."
	# Try graceful shutdown
	(bin/shutdown_linux_tao 2>/dev/null | grep -v "^Aborted$") || true
	sleep 1

	# Try to shutdown 
	killed=0
	for prog in $TAO_PROGRAMS; do
		if pgrep -lx `shortname "$prog"`; then
			pkill -x `shortname "$prog"`
			killed=1
		fi
	done
	if [ $killed -eq 1 ]; then
		sleep 1
		echo "Attempted to kill remaining Tao services and processes"
	else
		echo "No Tao services or processes remaining"
	fi
	rm -f *_socket */*_socket
}

function setup()
{
	rm -f bin
	ln -s ${TAO_BUILD} bin
	mkdir -p logs

	$admin -init ${TAO_ROOT}/run/tao-default.config -name testing 
	grep -v "^export GOOGLE_HOST_TAO" tao.env >/tmp/tao_env
	if [ "$TAO_USE_TPM" == "yes" ]; then
		echo "Creating TPMTao AIK and settings."
		rm -rf tpm
		$tpm_tao --path tpm --pcrs=$TAO_TPM_PCRS --create --noshow
		$tpm_tao --path tpm --show >> /tmp/tao_env
		source /tmp/tao_env
	else
		echo "Creating SoftTao key and settings."
		rm -rf soft_tao
		$soft_tao --path soft_tao --pass=$TAO_PASS --create --noshow
		$soft_tao --path soft_tao --pass=$TAO_PASS --show >> /tmp/tao_env
	fi
	mv /tmp/tao_env tao.env

	# TODO(kwalsh) set up ACLs here
	#$admin -whitelist ${TAO_HOSTED_PROGRAMS// /,}
	#$admin -newusers tmroeder,jlm
	#$admin -signacl ${TAO_ROOT}/run/acls.ascii -acl_sig_path acls_sig
	#mkdir -p file_client_files
	#mkdir -p file_server_files
	#mkdir -p file_server_meta
	echo "Tao configuration is ready"
}

function refresh()
{
	$admin -refresh -whitelist ${TAO_HOSTED_PROGRAMS// /,}
}

function startsvcs()
{
	# TODO(kwalsh) tcca
	# if pgrep -x `shortname tcca` >/dev/null; then
	# 	echo "TCCA service already running";
	# else
	# 	bin/tcca $admin_args &
	# 	sleep 1
	# 	echo "TCCA service now running"
	# fi

	if pgrep -x `shortname linux_tao` >/dev/null; then
		echo "LinuxHost service already running";
	else
		bin/linux_tao &
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
	if [ "${PIPESTATUS[0]}" != 0 ]; then false; fi
}

function base64wdecode()
{
	cat "$1" | tr "_-" "/+" | base64 -d
	if [ "${PIPESTATUS[0]}" != 0 ]; then false; fi
}

function base64wencode()
{
	cat "$1" | base64 | tr '/+' '_-' | tr -d '=' 
	if [ "${PIPESTATUS[0]}" != 0 ]; then false; fi
}

function testpgm()
{
	case "$1" in
		client|server)
			echo "Starting cloudproxy server..."
			server_id=`$start_hosted bin/server -- --v=2`
			echo "$server_id";
			server_pid=`extract_pid $server_id`
			sleep 2
			tail -f $GLOG_log_dir/server.INFO &
			server_tail_pid=$!
			echo "Starting cloudproxy client..."
			client_id=`$start_hosted  bin/client -- --v=2`
			client_pid=`extract_pid $client_id`
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
			server_id=`$start_hosted  bin/fserver -- --v=2`
			server_pid=`extract_pid $server_id`
			sleep 2
			tail -f $GLOG_log_dir/fserver.INFO &
			server_tail_pid=$!
			echo "Starting cloudproxy file client..."
			client_id=`$start_hosted  bin/fclient -- --v=2`
			client_pid=`extract_pid $client_id`
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
			server_id=`$start_hosted  bin/http_echo_server -- --v=2`
			server_pid=`extract_pid $server_id`
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
			server_id=`$start_hosted  bin/https_echo_server -- --v=2`
			server_pid=`extract_pid $server_id`
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
	base64w-encode.sh)
		for f in "$@"; do
			base64wencode $f
		done
		;;
	base64w-decode)
		for f in "$@"; do
			base64wdecode $f
		done
		;;
	help|*)
		cat <<END
Scripts in $TAO_TEST/scripts:
  setup.sh               # Re-initialize all keys, whitelists, configuration, etc.
  start.sh               # Start Tao services.
  restart.sh             # Restart Tao services.
  monitor.sh             # Watch binaries and restart Tao services as needed.
  test.sh <prog>         # Run tests for <prog>. Use prog "help" for choices.
  refresh.sh             # Refresh hashes and whitelists, but keep existing keys.
  stop.sh                # Kill processes, remove logs.
  clean.sh               # Remove all keys, configuration, logs, etc.
  hash.sh [file...]      # Hash files; use - for stdin.
  base64w-*.sh [file...] # Encode/decode files; use - for stdin.
END
		exit 0
		;;
esac

