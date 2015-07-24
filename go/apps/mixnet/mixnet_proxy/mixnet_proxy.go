// Copyright (c) 2015, Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"

	"github.com/golang/glog"
	"github.com/jlmucb/cloudproxy/go/apps/mixnet"
)

// Command line arguments.
var serverAddr = flag.String("addr", "localhost:8123", "Address and port for Tao server.")
var serverNetwork = flag.String("network", "tcp", "Network protocol for Tao server.")
var configPath = flag.String("config", "tao.config", "Path to domain configuration file.")

func main() {
	flag.Parse()
	p, err := mixnet.NewProxyContext(*configPath)
	if err != nil {
		glog.Fatalf("failed to configure proxy: %s", err)
	}

	c, err := p.DialRouter(*serverNetwork, *serverAddr)
	if err != nil {
		glog.Fatalf("failed to connect to router: %s", err)
	}
	defer c.Close()

	if _, err = c.Write([]byte("Hello!")); err != nil {
		glog.Errorf("failed to send message: %s", err)
	}

	glog.Flush()
}
