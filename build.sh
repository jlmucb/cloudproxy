#!/bin/sh
# Copyright (c) 2014, Google, Inc. All rights reserved.
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


# There are two separate builds to run here: one is the Go build for all the Go
# code currently in the repo, including apps and libraries. The other is the
# CMake build that provides support for building C++ applications that can talk
# to the a Go Tao using protobuf RPC.

# This assumes the GOPATH is properly set up to include the current directory as
# github.com/jlmucb/cloudproxy. We need to build in this mode to support running
# in Docker containers built over the scratch container: these don't have
# anything in them at all.
echo "Building Go libaries and applications"
CGO_ENABLED=0 go install -a -ldflags '-s' github.com/jlmucb/cloudproxy/...

echo "To build the C++ support, change directories to src and follow the instructions in the README.md"
