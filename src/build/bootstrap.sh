#!/bin/bash

# run this program from fileProxy/src as build/bootstrap.sh

echo Building ninja
(cd third_party/ninja && ./bootstrap.py)

echo Configuring ninja build files
(PATH=${PATH}:`pwd`/third_party/gyp GYP_GENERATORS=ninja gyp build/all.gyp --toplevel-dir=`pwd`)

echo To build, execute the command 'third_party/ninja/ninja -C out/Default'
