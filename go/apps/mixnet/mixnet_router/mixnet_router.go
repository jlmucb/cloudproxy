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
	"bufio"
	"crypto/x509/pkix"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jlmucb/cloudproxy/go/apps/mixnet"
	"github.com/jlmucb/cloudproxy/go/tao"
)

// serveMixnetProxies runs the mixnet router service for mixnet proxies.
// The proxy dials the Tao-delegated router anonymously, sends a message,
// and waits for a response.
func serveMixnetProxies(r *mixnet.RouterContext) error {
	go r.HandleErr()
	for {
		_, err := r.Accept()
		if err != nil {
			return err
		}
	}
}

// Command line arguments.
var (
	routerAddr      = flag.String("addr", "127.0.0.1:8123", "Address and port for the Tao-delegated mixnet router.")
	directories     = flag.String("dirs", "directories", "File containing addresses of directories.")
	routerNetwork   = flag.String("network", "tcp", "Network protocol for the Tao-delegated mixnet router.")
	configPath      = flag.String("config", "tao.config", "Path to domain configuration file.")
	batchSize       = flag.Int("batch", 1, "Number of senders in a batch.")
	timeoutDuration = flag.String("timeout", "10s", "Timeout on TCP connections, e.g. \"10s\".")
)

// x509 identity of the mixnet router.
var x509Identity pkix.Name = pkix.Name{
	Organization:       []string{"Google Inc."},
	OrganizationalUnit: []string{"Cloud Security"},
}

func main() {
	flag.Parse()
	timeout, err := time.ParseDuration(*timeoutDuration)
	if err != nil {
		log.Fatalf("router: failed to parse timeout duration: %s\n", err)
	}

	f, err := os.Open(*directories)
	if err != nil {
		log.Fatal(err)
	}
	scan := bufio.NewScanner(f)
	dirs := []string{}
	for scan.Scan() {
		dirs = append(dirs, scan.Text())
	}

	r, err := mixnet.NewRouterContext(*configPath, *routerNetwork, *routerAddr,
		timeout, dirs, *batchSize, &x509Identity, tao.Parent())
	if err != nil {
		log.Fatalln("failed to configure router:", err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	go func() {
		sig := <-sigs
		r.Close()
		log.Println("router: closing on signal:", sig)
		signo := int(sig.(syscall.Signal))
		os.Exit(0x80 + signo)
	}()

	if err := serveMixnetProxies(r); err != nil {
		log.Fatalln("router: error while serving:", err)
	}
}
