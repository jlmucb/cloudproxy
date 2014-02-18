CloudProxy
==========

Setup
-----

This project depends on several third-party libraries, which are
installed in third_party: keyczar, protobuf, google-glog, gflags,
ninja, and gyp. The openssl and TSPI development libraries must also be
installed. On Ubuntu, this can be accomplished with the command

    sudo apt-get install libssl-dev libtspi-dev


Build Process
-------------

To build CloudProxy, you must first build ninja and set up ninja build
files using gyp. Let SRC be the directory that contains this README
file. Then the build configuration can be accomplished with the
command:

    cd $SRC
    ${SRC}/build/bootstrap.sh.

To update the build after any change to a .gyp file, call gyp from the src
directory. To get this to work, you have to have gyp in your path:

    cd $SRC
    export PATH=${PATH}:`pwd`/third_party/gyp

Then in the $SRC directory, you can call gyp to fix up the build files

    GYP_GENERATORS=ninja gyp build/all.gyp --toplevel-dir=`pwd`

And if you have ninja in your path, then you can build directly from the $SRC
directory.

    ninja -C out/Release


Code Style
----------

The C++ sources in $SRC are formatted in accordance with Google style
guidelines. One easy way to make any changes match this format is to
use clang-format; a version built for x86-64 linux is checked in to
${ROOT}/bin/clang-format. The following command will reformat file.cc
in place:

    ${ROOT}/bin/clang-format --style=Google -i file.cc

Note, however, that clang-format does not rename anything to match the naming
conventions. Please see the files themselves for these conventions.


Documentation
-------------

This version of CloudProxy has documentation in doxygen format. To build it, you
must have doxygen installed. It helps to have the dot tool (from graphviz) as
well. Once these are installed, you can build the documentation as follows:

    cd $SRC
    doxygen build/Doxyfile

This will produce html documentation in ${ROOT}/doc/html. See the file
index.html to get started.


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
