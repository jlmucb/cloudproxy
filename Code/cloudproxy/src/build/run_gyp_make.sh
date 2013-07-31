#!/bin/bash

GYP_GENERATORS=make gyp build/cloudproxy.gyp --toplevel-dir=`pwd`
