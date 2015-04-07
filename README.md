CloudProxy
==========

CloudProxy implements a system for trustworthy computing. The core abstraction
of CloudProxy is the Tao, an API for trustworthy computing. The Tao can be
implemented by diverse components, including hardware, operating systems,
virtual-machine monitors, and applications. Any code that can make calls to an
implementation of the Tao can provide the Tao as well. So, an implementation of
the Tao can depend recursively on lower-level Tao implementations. Code that
provides the Tao is called a _host_ and code running on a host is called a
_hosted program_.

The Tao provides three main operations: Seal, Unseal, and Attest. Seal and
Unseal are like encryption and decryption, except that Seal and Unseal can have
policies for unsealing sealed data. For example, a Tao implementation might
be willing to unseal data only for the code that originally sealed the data. The
Attest operation provides cryptographic evidence of the _code identity_ of a
hosted program. For example, if the Tao host is a Trusted Platform Module, then
attestation might be performed for a Linux operating system executing as a
hosted program. In this case, the attestation would contain a signed TPM Quote2
for appropriate Platform Configuration Registers (PCRs). In this case, the PCRs
contain information about the hash of the operating-system code.

Software components in a CloudProxy-based system execute in the context of a
_security domain_. This domain is rooted in one or more cryptographic _policy
keys_ and provides signed policy statements about the kinds of hosts and hosted
programs that are allowed to run. These statements make use of the code identity
of hosts and hosted programs; the hash of a binary often forms a large part of
the code identity of the software component using the binary.

Policy statements are managed by a _policy guard_, which interprets statements
and provides answers to authorization queries. The current implementation of
CloudProxy has an ACL-based guard and a Datalog one.

Code
====

The `tao` directory holds the Tao implementation, including subdirectories for
an authorization language (`auth`) and networking (`net`). The `run/scripts`
directory has scripts that are useful for setting up instances of example
applications from `apps`. The `util` directory is a library of utilities used by
the `tao` library.

The `apps` directory also includes programs for Tao deployment and
administration:

- `linux_host` provides the Tao to three types of hosted program:
  1. processes running on Linux
  2. Docker containers running on Linux
  3. CoreOS virtual machines running on Linux/KVM
- `tao_admin` can set up new domains, add and remove signed policy
    statements, query the policy guard, and generate keys.
- `tao_launch` launches all supported types of hosted programs, given a
    path to the Unix domain socket for `linux_host`.
- `tcca` is a certificate authority for Tao connections. It provides
  certificates and short attestations to hosted programs.

Demo
====

The simplest demo in CloudProxy consists of a client that sends messages to a
server and a server that echoes the messages back. This application is
implemented in `apps/demo`. The demo application requires a security domain and
a policy that allows the `demo_server` and `demo_client` binaries to run. The
policy statements in `run/scripts/domain_template.pb` are sufficient if
CloudProxy is built and installed using `run/scripts/build_standalone.sh`.

To create a domain, run the `run/scripts/set_up_domain.sh` script and supply the
name of a guard type: `Datalog`, `ACLs`, or `AllowAll`. The last option (only
for debugging) creates a guard that returns true for any authorization query.
The opposite policy `DenyAll` is implemented but doesn't run, since the
application stops due to authorization failure. The `set_up_domain.sh` script
outputs the directory name of a domain that it created. This directory name is
needed to run the demo. For example, to get a domain with policy based on
Datalog, run the command

	run/scripts/set_up_domain.sh Datalog

The `set_up_domain.sh` script uses `run/scripts/domain_template.pb` to configure
the domain. This text-format protobuf structure contains rules and paths to
binaries. Relative paths in the domain template are taken to be relative to
`${GOPATH}/bin`; absolute paths are also permitted.

There are three demo configurations: Linux processes, Docker containers, and
KVM/CoreOS virtual machines. These correspond to the `run/scripts/run_*.sh`
scripts. All three scripts require `sudo` privileges (to start `linux_host`) and
require that the CloudProxy Go binaries were built in for a standalone
environment and have been installed in `${GOPATH}/bin`. This can be accomplished
using the script `run/scripts/build_standalone.sh`.

Let the generated domain directory be `$DOMAIN`. Then to start the Linux process
demo, run the command

	run/scripts/run_processes.sh $DOMAIN

The Docker-based demo assumes that `$PATH` contains a Docker binary called
`docker`. To start the Linux Docker demo, run the command

	run/scripts/run_docker.sh $DOMAIN

The KVM/CoreOS demo assumes that `$PATH` contains a QEMU binary called
`qemu-system-x86_64`. It also requires a CoreOS virtual-machine image (call it
`$IMG`), a file containing at least one SSH public key (call it `$KEYFILE`), and
a running SSH agent that holds a private key corresponding to one of the keys in
`$KEYFILE`. The CoreOS image should be referenced in `domain_template.pb` in
`vm_paths`. If all these requirements are satisfied, then the Linux KVM/CoreOS
demo can be started by running the command

	run/scripts/run_kvm.sh $IMG $KEYFILE $DOMAIN
