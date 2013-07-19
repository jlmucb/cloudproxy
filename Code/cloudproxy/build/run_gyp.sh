#!/bin/bash

GYP_GENERATORS=ninja gyp build/cloudproxy.gyp --toplevel-dir=`pwd`
