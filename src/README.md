CloudProxy
==========

The files in this directory are only used to allow C++-based applications to run
as hosted programs under the Tao. In other words, this is not the directory you
are looking for. See ../go for the core Tao libraries and applications based on
it.

Setup
-----

The C++ client library for CloudProxy depends on third-party libraries installed
in `third_party`: google-glog, gflags, and several others. Additionally,
OpenSSL, and Protobuf development libraries must be installed, along with the
CMake build system. On Ubuntu, these can be installed with the command:

    sudo apt-get install libssl-dev libprotoc-dev cmake ninja-build libvirt-dev libtspi-dev

Note: CloudProxy relies on newer versions of the protobuf 'protoc' compiler.
Version of protoc prior to version 2.5.0 that are packaged for some Ubuntu
systems may not work.


Build Process
-------------

Let SRC be the directory that contains this README.md file.  To build
CloudProxy, you create a build directory and call cmake then ninja from within
it.

    mkdir ${SRC}/out
    cd ${SRC}/out
    cmake -G Ninja ..
    ninja

The ninja build process updates the build if any CMakeLists.txt files were
changed, so there is usually no need to rerun CMake.

Code Style
----------

The C++ sources are formatted in accordance with [Google style
guidelines](https://google-styleguide.googlecode.com/svn/trunk/cppguide.html).
One easy way to make changes match this format is to use clang-format. On
Ubuntu, you can install clang-format using:

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
