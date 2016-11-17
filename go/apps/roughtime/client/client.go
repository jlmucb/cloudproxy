// Copyright (c) 2016, Google Inc. All rights reserved.
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

// this is an adapted version of the client code to cnonect to cloudproxy.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"roughtime.googlesource.com/go/config"

	"github.com/jlmucb/cloudproxy/go/apps/roughtime"
)

var (
	chainFile    = flag.String("chain-file", "roughtime-chain.json", "The name of a file in which the query chain will be maintained")
	maxChainSize = flag.Int("max-chain-size", 128, "The maximum number of entries to maintain in the chain file")
	serversFile  = flag.String("servers-file", "roughtime-servers.json", "The name of a file that lists trusted Roughtime servers")
	configPath   = flag.String("config", "tao.config", "Path to domain configuration file.")
)

const (
	// defaultServerQuorum is the default number of overlapping responses
	// that are required to establish the current time.
	defaultServerQuorum = 2
)

func main() {
	serversData, err := ioutil.ReadFile(*serversFile)
	if err != nil {
		log.Fatal(err)
	}

	servers, numServersSkipped, err := roughtime.LoadServers(serversData)
	if err != nil {
		log.Fatal(err)
	}
	if numServersSkipped > 0 {
		fmt.Fprintf(os.Stderr, "Ignoring %d unsupported servers\n", numServersSkipped)
	}

	c, err := roughtime.NewClient(*configPath, "tcp", defaultServerQuorum, servers)

	// Read existing chain, if one exists
	chain := &config.Chain{}
	chainData, err := ioutil.ReadFile(*chainFile)
	if err == nil {
		if chain, err = roughtime.LoadChain(chainData); err != nil {
			log.Fatal(err)
		}
	} else if !os.IsNotExist(err) {
		log.Fatal(err)
	}

	chain, err = c.Do(chain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	chainBytes, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	tempFile, err := ioutil.TempFile(filepath.Dir(*chainFile), filepath.Base(*chainFile))
	if err != nil {
		log.Fatal(err)
	}
	defer tempFile.Close()

	if _, err := tempFile.Write(chainBytes); err != nil {
		log.Fatal(err)
	}

	if err := os.Rename(tempFile.Name(), *chainFile); err != nil {
		log.Fatal(err)
	}
}
