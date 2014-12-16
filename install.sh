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
# This script works with the Go implementation of Tao. It assumes all binaries
# have been installed in ${GOPATH}/bin (e.g. via `go install`)
#
# If you wish to use the TPM, you must have taken ownership of the TPM.

set -e # quit script on first error

# INSTALL BEGIN
# Note: This section of code is removed by install.sh
script_path="install.sh"
test_dir=""
test_tpm="no"
verbose="yes"
test_guard="AllowAll"
for arg in "$@"; do
	case "$arg" in
		-notpm)
			test_tpm="no"
			shift
			;;
		-tpm)
			test_tpm="yes"
			shift
			;;
		-acls)
			test_guard="ACLs"
			shift
			;;
		-datalog)
			test_guard="Datalog"
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
	echo "  if it does not yet exist. If neither -acls nor -datalog is"
	echo "  specified, then the authorization policy is AllowAll."
	echo "Options:"
	echo "  -notpm       Use a fake TPM (the default)."
	echo "  -tpm         Use the TPM."
	echo "  -acls        Use ACL-based guards for Tao domain policy."
	echo "  -datalog     Use Datalog-based guards for Tao domain policy."
	echo "  -q           Be more quiet."
	exit 1
fi
if [ -e "$test_dir" -a ! -d "$test_dir" ]; then
	echo "$test_dir: path exists but is not a directory"
	exit 1
fi
mkdir -p "$test_dir"
# canonicalize
root_dir="$(dirname $0)"
test_dir="$test_dir"
if [ "$verbose" == "yes" ]; then
	echo "Installing tao test scripts into: $test_dir"
fi
# sanity checks
if [ ! -d "$GOPATH/bin" ]; then
    echo "install failed: could not find GOPATH bin directory"
    exit 1
fi
if [ ! -f "$root_dir/$script_path" -o ! -d "$test_dir" ]; then
	echo "install failed: could not canonicalize paths"
	exit 1
fi
mkdir -p "$test_dir/scripts"
rm -f "$test_dir/scripts/tao.sh"
sed '/^# INSTALL BEGIN/,/^# INSTALL END/ s/^/## /' "$root_dir/$script_path" \
			>"$test_dir/scripts/tao.sh"
chmod +x "$test_dir/scripts/tao.sh"
	
cd "$test_dir/scripts/"
perl -p -i -e "s|^export TAO_TEST=undef .*\$|export TAO_TEST="\""$test_dir"\""|" tao.sh
for script in "setup.sh" "start.sh" "restart.sh" "monitor.sh" \
	"test.sh" "refresh.sh" "stop.sh" "clean.sh" "hash.sh" "help.sh" \
	"host.sh" "base64w-encode.sh" "base64w-decode.sh"; do
	rm -f $script
	ln -s tao.sh $script
done
cd "$test_dir"
rm -f bin
ln -s ${GOPATH}/bin bin
mkdir -p logs

if [ "$test_tpm" == "yes" ]; then
	test_root=false
	test_stacked=true
else
	test_root=true
	test_stacked=false
fi

cat <<END > "$test_dir/tao.env"
# Tao/CloudProxy environment variables"
export TAO_TEST="$test_dir" # Also hardcoded into $test_dir/scripts/*.sh
export TAO_ROOTDIR="$root_dir"
export TAO_USE_TPM="$test_tpm"

# Flags for tao programs
export TAO_config_path="${test_dir}/tao.config"
export TAO_guard="$test_guard"

# Flags for tao_admin
export TAO_ADMIN_pass="BogusPass"

# Flags for linux_host
export TAO_HOST_pass="BogusPass"
export TAO_HOST_root="$test_root"
export TAO_HOST_stacked="$test_stacked"
export TAO_HOST_path="${test_dir}/linux_tao_host"

# Flags for tpm_tao
export TAO_TPM_path="${test_dir}/tpm"
export TAO_TPM_pcrs="17,18"

# Flags for glog
export GLOG_v=2
export GLOG_logtostderr="no"
export GLOG_alsologtostderr="no"
export GLOG_stderrthreshold=3 # Only log FATAL to stderr.
export GLOG_log_dir="\${TAO_TEST}/logs"

# Misc.
export TAO_HOSTED_PROGRAMS="
\${TAO_TEST}/bin/demo 
\${TAO_TEST}/bin/demo_server
\${TAO_TEST}/bin/client 
\${TAO_TEST}/bin/server 
\${TAO_TEST}/bin/fclient 
\${TAO_TEST}/bin/fserver 
\${TAO_TEST}/bin/http_echo_server 
\${TAO_TEST}/bin/https_echo_server 
"

# BEGIN SETUP VARIABLES
# These variables come from $test_dir/scripts/setup.sh
export GOOGLE_HOST_TAO=""
# END SETUP VARIABLES
END

if [ "$verbose" == "yes" ]; then
	cat <<END
Done installing. 
  $test_dir/bin               # Link to ${GOPATH}/bin.
  $test_dir/logs              # Log files.
  $test_dir/scripts           # Useful scripts.
  $test_dir/tao.env           # Environment variables.
Typical next steps:
  cd $test_dir/
  ./scripts/setup.sh          # Create keys, hashes, ACLs, etc.
  ./scripts/start.sh          # Run Tao CA and Linux Tao server.
  ./scripts/host.sh demo      # Run a client/server demo test.
  ./scripts/stop.sh           # Kill all Tao programs.
  ./scripts/refresh.sh        # Refresh hashes, ACLs, etc.
Run $test_dir/scripts/help.sh for more info.
END
fi

exit 0

# INSTALL END

export TAO_TEST=undef # replaced with path to test dir by install.sh

tao_env=${TAO_TEST}/tao.env
if [ ! -f ${tao_env} ]; then
	echo "Missing ${tao_env}"
	exit 1
fi
source ${tao_env}

PATH="${TAO_TEST}/bin:$PATH"

# nb: cat at the end of pipeline hides exit code of grep -v
all_tao_progs=$(cd ${TAO_TEST}/bin; echo * | grep -v '\.a$' | grep -v 'log_net_server' | cat) # exclude lib*.a
watchfiles="bin/linux_host acls rules tao.config tao.env"

function extract_pid()
{
	childname="$1"
	pid=`echo "$childname" | sed 's/^Success: Program([0-9]\+, ".*", ".*", ".*")::PID(\([0-9]\+\))$/\1/'`
	echo "$pid"
}

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
	cat ${tao_env}
}

function cleanup()
{
	rm -f ${TAO_TEST}/logs/*
	rm -rf ${TAO_TEST}/{*keys,linux_tao_host,acls,rules,tao.config}
	sed -i.bak '/^# BEGIN SETUP VARIABLES/,/^# END SETUP VARIABLES/d' ${tao_env}
	echo "# BEGIN SETUP VARIABLES" >> ${tao_env}
	echo "# These variables come from ${TAO_TEST}/scripts/setup.sh" >> ${tao_env}
	echo 'export GOOGLE_HOST_TAO=""' >> ${tao_env}
	echo "# END SETUP VARIABLES" >> ${tao_env}

	echo "Cleared all Tao configuration data"
}

function stoptests()
{
	echo "Attempting graceful shutdown..."
	(if linux_host --shutdown; then sleep 1; fi ) 2>/dev/null | grep -v "^Aborted$" || true
	
	echo "Checking for remaining Tao services and processes..."
	# Try to shutdown 
	killed=0
	for prog in $all_tao_progs; do
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
	rm -f ${TAO_TEST}/linux_tao_host/admin_socket ${TAO_TEST}/*/*_socket
}

function setup()
{
	mkdir -p ${TAO_TEST}/logs

	echo "Creating TaoDomain keys and settings."
	tao_admin -create -name testing

	# This sets:
	# $GOOGLE_HOST_TAO # name of underlying host tao, i.e. the TPM (if any)
	# GOOGLE_TAO_TPM, GOOGLE_TAO_PCRS, # more details about TPM (if any)
	# and GOOGLE_TAO_LINUX # name of the LinuxHost
	sed -i.bak '/^# BEGIN SETUP VARIABLES/,/^# END SETUP VARIABLES/d' ${tao_env} 
	echo "# BEGIN SETUP VARIABLES" >> ${tao_env}
	echo "# These variables come from ${TAO_TEST}/scripts/setup.sh" >> ${tao_env}

	if [ "$TAO_USE_TPM" == "yes" ]; then
        # Don't create a new AIK if one is already present.
        echo "Checking ${TAO_TEST}/tpm/aikblob"
        pcr17=`tao_admin -getpcr 17`
        pcr18=`tao_admin -getpcr 18`
        if [ ! -f ${TAO_TEST}/tpm/aikblob ]; then
            echo "Creating TPMTao AIK and settings."
            rm -rf ${TAO_TEST}/tpm
            tpm_tao --create --show=false
        else
            echo "Reusing existing TPMTao AIK."
            export GOOGLE_HOST_TAO='tao::TPMTao("dir:tpm")'
            export GOOGLE_TAO_PCRS='PCRs("17,18", "'${pcr17}','${pcr18}'")'
        fi

        tprin=`tao_admin -aikblob ${TAO_TEST}/tpm/aikblob`
        export GOOGLE_TAO_TPM=$tprin

        # TODO(tmroeder): do this correctly in the Go version once we support
        # AIK creation.
        echo "export GOOGLE_HOST_TAO='tao::TPMTao(\"dir:tpm\")'" >> ${tao_env}
        echo "export GOOGLE_TAO_PCRS='PCRs(\"17,18\", \"${pcr17},${pcr18}\")'" >> ${tao_env}
        echo "export GOOGLE_TAO_TPM='$tprin'" >> ${tao_env}
	fi

	echo "Creating LinuxHost keys and settings."
	rm -rf ${TAOHOST_path}
	linux_host --create --show=false
	linux_host --show >> ${tao_env}

	echo "# END SETUP VARIABLES" >> ${tao_env}

    echo "Refreshing"
	refresh
}

function refresh()
{
	source ${tao_env}

	# Set up default execution policy.
	tao_admin -clear
	if [ "${TAO_guard}" == "Datalog" ]; then
		# Rule for TPM and PCRs combinations that make for a good OS
		tao_admin -add "(forall S: forall TPM: forall PCRs: TrustedPlatform(TPM) and TrustedKernelPCRs(PCRs) and Subprin(S, TPM, PCRs) implies TrustedOS(S))"
		# Rule for OS and program hash that make for a good hosted program
		tao_admin -add "(forall P: forall OS: forall Hash: TrustedOS(OS) and TrustedProgramHash(Hash) and Subprin(P, OS, Hash) implies MemberProgram(P))"
		# Rule for programs that can execute
		tao_admin -add "(forall P: MemberProgram(P) implies Authorized(P, \"Execute\"))"
		# Rule for programs with Args subprincipals
		tao_admin -add "(forall Y: forall P: forall S: MemberProgram(P) and TrustedArgs(S) and Subprin(Y, P, S) implies Authorized(Y, \"Execute\"))"
		# Add the TPM keys, PCRs, and/or LinuxHost keys
		if [ "$TAO_USE_TPM" == "yes" ]; then
			tao_admin -add 'TrustedPlatform('${GOOGLE_TAO_TPM}')'
			# Escape the spaces and quotes in the string so it can be passed as
			# a single argument to tao_admin
			trustedpcrs=`echo 'TrustedKernelPCRs(ext.'${GOOGLE_TAO_PCRS}')' | sed 's/ /\\ /g' | sed 's/"/\\"/g'`
			tao_admin -add "$trustedpcrs"
		else
			tao_admin -add 'TrustedOS('${GOOGLE_TAO_LINUX}')'
		fi
		# Add the program hashes, assuming LinuxHost and LinuxProcessFactory.
		for prog in ${TAO_HOSTED_PROGRAMS}; do
			if [ -f "$prog" ]; then
				proghash=`tao_admin -quiet -getprogramhash "$prog"`
				tao_admin -add 'TrustedProgramHash(ext'${proghash}')'
				tao_admin -add 'TrustedArgs(ext.Args("'$prog'"))'
				tao_admin -add 'TrustedArgs(ext.Args("'$prog'", "-ca=localhost:8124"))'
			fi
		done
	else
		for prog in ${TAO_HOSTED_PROGRAMS}; do
			if [ -f "$prog" ]; then
				tao_admin -canexecute "$prog"
			fi
		done
	fi
	tao_admin -show

	# TODO(kwalsh) set up fserver user ACLs here.
	#tao_admin -newusers tmroeder,jlm
	#tao_admin -signacl ${TAO_ROOTDIR}/run/acls.ascii -acl_sig_path user_acls_sig
	#mkdir -p file_client_files
	#mkdir -p file_server_files
	#mkdir -p file_server_meta

	echo "Tao configuration is ready"
}

function startsvcs()
{
	if pgrep -x `shortname linux_host` >/dev/null; then
		echo "LinuxHost service already running";
	else
		rm -f ${TAO_TEST}/linux_tao_host/admin_socket
		linux_host --service &
	fi
}

function monitor()
{
	echo "Monitoring Tao files..."
	(
		cd ${TAO_TEST}
		while true; do
			inotifywait -e modify -e delete -e attrib $watchfiles >/dev/null 2>&1
			echo "Files have changed, waiting for quiet..."
			sleep 1
			while inotifywait -t 3 -e modify -e delete -e attrib $watchfiles >/dev/null 2>&1; do
				echo "Still waiting for quiet..."
				sleep 1
			done
			echo "Restarting Tao services..."
			refresh
			stoptests
			startsvcs
		done
	)
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
	cd ${TAO_TEST} # These take no params and must be run within test directory
	case "$1" in
		client|server)
			echo "Starting cloudproxy server..."
			server_id=`linux_host -run -- server --v=2`
			echo "$server_id";
			server_pid=`extract_pid $server_id`
			sleep 2
			tail -f $GLOG_log_dir/server.INFO &
			server_tail_pid=$!
			echo "Starting cloudproxy client..."
			client_id=`linux_host -run -- client --v=2`
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
			server_id=`linux_host -run -- fserver --v=2`
			server_pid=`extract_pid $server_id`
			sleep 2
			tail -f $GLOG_log_dir/fserver.INFO &
			server_tail_pid=$!
			echo "Starting cloudproxy file client..."
			client_id=`linux_host -run -- fclient --v=2`
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
			server_id=`linux_host -run -- http_echo_server --v=2`
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
			server_id=`linux_host -run -- https_echo_server --v=2`
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
		help|*)
			echo "Available test programs:"
			echo "  demo        # a simple demo (run with host.sh)"
			echo "  server      # cloud client/server test (not ported yet)"
			echo "  fserver     # file client/server test (not ported yet)"
			echo "  http        # http echo test (not ported yet)"
			echo "  https       # https echo test (not ported yet)"
			;;
	esac
}

function hostpgm()
{
	prog="$1"
	shift
	echo "Starting hosted program $prog ..."
	prog_id=`linux_host -run -- "$prog" "$@"`
	echo "TaoExtension: $prog_id"
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
	host.sh)
		if [ "$#" == "0" ]; then
			echo "usage: $0 <prog> [arg...]"
		else
			hostpgm "$@"
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
	base64w-decode.sh)
		for f in "$@"; do
			base64wdecode $f
		done
		;;
	help|*)
		cat <<END
Scripts in $TAO_TEST/scripts:
  setup.sh                 # Re-initialize all keys, whitelists, configuration, etc.
  start.sh                 # Start Tao services.
  restart.sh               # Restart Tao services.
  monitor.sh               # Watch binaries and restart Tao services as needed.
  test.sh <test>...        # Run one or more <test> cases. Use test.sh "help" for choices.
  host.sh <prog> [arg...]  # Run <prog> with arguments as hosted program.
  refresh.sh               # Refresh hashes and whitelists, but keep existing keys.
  stop.sh                  # Kill processes, remove logs.
  clean.sh                 # Remove all keys, configuration, logs, etc.
  hash.sh [file...]        # Hash files; use - for stdin.
  base64w-*.sh [file...]   # Encode/decode files; use - for stdin.
END
		exit 0
		;;
esac

