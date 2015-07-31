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
	"crypto/x509/pkix"
	"flag"
	"io"
	"net"
	"time"

	"github.com/golang/glog"
	"github.com/jlmucb/cloudproxy/go/apps/mixnet"
	"github.com/jlmucb/cloudproxy/go/tao"
)

// Handle connections from mixnet clients.
func handleMixnetClient(conn net.Conn, ch chan<- error) {
	// TODO(cjpatton) for now, just receive a cell.
	cell := make([]byte, mixnet.CellBytes)
	if _, err := conn.Read(cell); err != nil {
		ch <- err
	}
	ch <- nil
}

// Run mixnet router service for mixnet clients.
// TODO(cjpatton) how to handle interrupts so that defers's are called? Tom:
// signal.Notify allows you to add new signal handlers for a given signal
// (without removing the old ones). So, you could wrap a deferred function in a
// signal handler to make sure it gets called (almost) no matter what.
func serveMixnetClients(hp *mixnet.RouterContext) error {
	ch := make(chan error)
	conn, err := hp.AcceptProxy()
	if err != nil {
		return err
	}
	defer conn.Close()

	go handleMixnetClient(conn, ch)

	return <-ch
}

// Command line arguments.
var serverAddr = flag.String("addr", "localhost:8123", "Address and port for Tao server.")
var serverNetwork = flag.String("network", "tcp", "Network protocol for Tao server.")
var configPath = flag.String("config", "tao.config", "Path to domain configuration file.")
var batchSize = flag.Int("batch", 2, "Number of senders in a batch.")

// x509 identity of the mixnet router.
var x509Identity pkix.Name = pkix.Name{
	Organization:       []string{"Google Inc."},
	OrganizationalUnit: []string{"Cloud Security"},
}

func main() {
	flag.Parse()
	timeout, _ := time.ParseDuration("5s") // TODO(cjpatton) make this a command line parameter.
	hp, err := mixnet.NewRouterContext(*configPath, *serverNetwork, *serverAddr, *batchSize,
		timeout, &x509Identity, tao.Parent())
	if err != nil {
		glog.Errorf("failed to configure server: %s", err)
	}
	defer hp.Close()

	if err = serveMixnetClients(hp); err != nil && err != io.EOF {
		glog.Errorf("error occured while serving: %s", err)
	}

	glog.Flush()
}
