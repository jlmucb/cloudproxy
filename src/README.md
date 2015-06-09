CloudProxy
==========

Setup
-----

CloudProxy depends on third-party libraries installed in third_party:
google-glog, gflags, ninja, and several others. Additionally, OpenSSL, TSPI, and
Protobuf development libraries must also be installed, along with the CMake
build system. On Ubuntu, these can be installed with the command:

    sudo apt-get install libssl-dev libtspi-dev libvirt-dev libprotoc-dev cmake

Note: CloudProxy relies on newer versions of the protobuf 'protoc' compiler.
Version of protoc prior to version 2.5.0 that are packaged for some Ubuntu
systems may not work. 


Build Process
-------------

Let SRC be the directory that contains this README.md file. 

To build CloudProxy, you must first build ninja and set up ninja build files
using cmake. This can be accomplished with the command:

    cd ${SRC} && ${SRC}/build/bootstrap.sh

To update the build after any change to a cmake file, invoke:

    cd ${SRC} && ${SRC}/build/config.sh

To compile CloudProxy, invoke:

    cd ${SRC} && ${SRC}/build/compile.sh 


Code Style
----------

The C++ sources in ${SRC} are formatted in accordance with Google style
guidelines. One easy way to make any changes match this format is to
use clang-format. On Ubuntu, you can install clang-format using:

    sudo apt-get install clang-format-3.4

The following command will then reformat file.cc in place:

    clang-format --style=Google -i file.cc

Note, however, that clang-format does not rename anything to match the naming
conventions. Please see the files themselves for these conventions.


Documentation
-------------

This version of CloudProxy has documentation in doxygen format. To build it, you
must have doxygen installed. It helps to have the dot tool (from graphviz) as
well. Once these are installed, you can build the documentation as follows:

    cd ${SRC} && doxygen build/Doxyfile

This will produce html documentation in ${SRC}/doc/html. See index.html to get
started.


Testing
-------

CloudProxy uses the Google Test framework for testing. Each library has a test
suite. Some tests will work only if certain conditions are met. For example, the
TPM tests require access to a TPM and an AIK in that TPM, and the KvmVmFactory
tests require KVM to be set up and certain files to be prepared. To run the
libtao test suite without these tests, you can specify a negative filter on the
command line. For example, to run all but the TPM and KvmVmFactory tests:

    ./out/Release/bin/tao_test -- --gtest_filter=-TPM*:KvmVmFactory*
    ./out/Release/bin/cloudproxy_test

All tests run using this filter should work on any machine that can build
CloudProxy.

Note that both gflags and gtest consume command line flags. The flags for gflags
(hence for the libraries themselves) must be passed first, followed by "--",
then the flags for gtest. So, the extra double dash in the first command above
is not a typo.

The integration testing infrastructure is still under construction. At the
moment, there are only two tests: a TPM-based test, and a fake test. For the
former, change the variables in `${SRC}/scripts/run_simple_tests.sh` for your
directory structure, cd to your testing directory and run the TPM test using:

    rm -fr run test && ~/src/fileProxy/src/scripts/set_up_keys.sh && cd test && ./run_simple_test.sh

Run the fake test using:

    rm -fr run test && ~/src/fileProxy/src/scripts/set_up_keys.sh FAKE && cd test && ./run_simple_fake_test.sh
