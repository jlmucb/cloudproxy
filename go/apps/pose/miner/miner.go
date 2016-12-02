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

	"github.com/jlmucb/cloudproxy/go/apps/pose"
	"github.com/jlmucb/cloudproxy/go/tao"
)

// Command line arguments.
var (
	network    = flag.String("network", "tcp", "Network protocol for the mixnet proxy and router.")
	addr       = flag.String("addr", "127.0.0.1:8000", "Peer facing address")
	configPath = flag.String("config", "tao.config", "Path to domain configuration file.")
	id         = flag.Int("id", 0, "A unique identifier")
	chainFile  = flag.String("chain", "/tmp/chain", "Chain file")
	peerFile   = flag.String("peers", "", "File containing peers")

	x509Identity pkix.Name = pkix.Name{
		Organization: []string{"CloudProxy Miner"},
	}
)

func main() {
	flag.Parse()

	miner, err := pose.NewMiner(*network, *addr, *configPath, &x509Identity, tao.Parent(), *chainFile)
	if err != nil {
		log.Fatalln("failed to configure proxy:", err)
	}
	defer miner.Close()

	// TODO(kwonalbert): somehow get the peer list if peer file is not given
	if *peerFile != "" {
		f, err := os.Open(*peerFile)
		if err != nil {
			log.Fatal(err)
		}
		scan := bufio.NewScanner(f)
		peers := []string{}
		for scan.Scan() {
			peers = append(peers, scan.Text())
		}
		miner.SetPeers(peers)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	go func() {
		sig := <-sigs
		miner.Close()
		log.Println("proxy: closing on signal:", sig)
		signo := int(sig.(syscall.Signal))
		os.Exit(0x80 + signo)
	}()
	err = miner.Protocol()
	if err != nil {
		log.Println(err)
	}
}
