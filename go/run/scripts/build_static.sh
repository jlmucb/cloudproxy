#!/bin/sh

# Docker requires static executables. This can be accomplished by either
# disabling cgo or using the netgo tag.
echo "Building static version of cloudproxy"
CGO_ENABLED=0 go install -a -installsuffix nocgo github.com/jlmucb/cloudproxy/...
