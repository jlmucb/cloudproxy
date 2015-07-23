Installing and Using a TPM Emulator
===================================

Instead of using a hardware TPM for testing, you can use a software TPM either
through the Linux kernel (and a specialized driver) or through a system daemon
accessed through a Unix domain socket. This document describes how to build and
run the tpm daemon and access it through a socket.

Getting the Source
------------------

The TPM Emulator was written by Mario Strasser at ETH Zurich and was originally
available at [BerliOS](http://tpm-emulator.berlios.de). However, that page no longer
responds, though it can be reached on the [Internet
Archive](https://web.archive.org/web/20140419212644/http://tpm-emulator.berlios.de/).
A version of the source exists [on
Github](https://github.com/PeterHuewe/tpm-emulator) and is also present in the
[ChromeOS public
repository](https://chromium.googlesource.com/chromiumos/third_party/tpm-emulator/).

Building the Source
-------------------

The tpm-emulator source uses CMake, so it can be built in multiple ways. We only
need `tpmd`, the daemon version of the tpm. So, we can cd into the tpm-emulator
directory and do something like the following:

	mkdir build
	cd build
	cmake ..
	make tpmd

The `tpmd` program will then be available in `build/tpmd/unix/tpmd`.

Running the Emulator
--------------------

The `tpmd` emulator stores its data in a file and uses a Unix domain socket for
communication. The latest version of the go-tpm library supports domain
socket-based communication. So, you can start the emulator as

	tpmd -s /path/to/storage/file -u /path/to/tpm/socket [clear|save|deactivated]

The `tpmd` program must be started in `clear` mode the first time, then in
`save` mode after. It can be treated as a TPM in those modes (e.g., you can take
ownership with `tpm-take-ownership` from the go-tpm project). The path to the
TPM can be given as part of a domain config.
