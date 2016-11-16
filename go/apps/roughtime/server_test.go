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

// This file contains tests for the adapted roughtime server and client
// Significant portion of this code is modified version of what is in
// the original roughtime repository
package roughtime

import (
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"

	"roughtime.googlesource.com/go/client/monotime"
	"roughtime.googlesource.com/go/config"
)

var (
	domainPath             = "roughttime_test_domain"
	network                = "tcp"
	maxChainSize           = 8
	x509Identity pkix.Name = pkix.Name{
		Organization:       []string{"Google Inc."},
		OrganizationalUnit: []string{"Cloud Security"},
	}
)

func makeTrivialDomain() (*tao.Domain, error) {
	var policyDomainConfig tao.DomainConfig
	policyDomainConfig.SetDefaults()
	policyDomainConfig.DomainInfo.GuardType = proto.String("AllowAll")
	configPath := path.Join(domainPath, "tao.config")
	return tao.CreateDomain(policyDomainConfig, configPath, []byte("xxx"))
}

func TestCreateChain(t *testing.T) {
	domain, err := makeTrivialDomain()
	if err != nil {
		log.Fatal(err)
	}

	tmpDir, err := ioutil.TempDir("", domainPath)
	if err != nil {
		log.Fatal(err)
	}
	st, err := tao.NewSoftTao(tmpDir, []byte("xxx"))
	if err != nil {
		log.Fatal(err)
	}

	numServers := 2
	servers := make([]config.Server, numServers)
	for i := 0; i < numServers; i++ {
		server, err := NewServer(domain.ConfigPath, network, 8000+i, &x509Identity, st)
		if err != nil {
			log.Fatal(err)
		}
		go server.ServeForever()
		serverCfg := config.Server{
			Name:          fmt.Sprintf("Test%d", i),
			PublicKeyType: "ed25519",
			PublicKey:     server.publicKey,
			Addresses:     []config.ServerAddress{config.ServerAddress{network, fmt.Sprintf("localhost:%d", 8000+i)}},
		}
		servers[i] = serverCfg
	}
	time.Sleep(time.Second)

	quorum := numServers
	if quorum > len(servers) {
		fmt.Fprintf(os.Stderr, "Quorum set to %d servers because not enough valid servers were found to meet the default (%d)!\n", len(servers), quorum)
		quorum = len(servers)
	}

	chain := &config.Chain{}
	client, err := NewClient(domain.ConfigPath, network)
	if err != nil {
		log.Fatal(err)
	}
	result, err := client.EstablishTime(chain, quorum, servers)
	if err != nil {
		log.Fatal(err)
	}

	for serverName, err := range result.ServerErrors {
		fmt.Fprintf(os.Stderr, "Failed to query %q: %s\n", serverName, err)
	}

	maxLenServerName := 0
	for name := range result.ServerInfo {
		if len(name) > maxLenServerName {
			maxLenServerName = len(name)
		}
	}

	for name, info := range result.ServerInfo {
		fmt.Printf("%s:%s %d–%d (answered in %s)\n", name, strings.Repeat(" ", maxLenServerName-len(name)), info.Min, info.Max, info.QueryDuration)
	}

	if result.MonoUTCDelta == nil {
		fmt.Fprintf(os.Stderr, "Failed to get %d servers to agree on the time.\n", quorum)
	} else {
		nowUTC := time.Unix(0, int64(monotime.Now()+*result.MonoUTCDelta))
		nowRealTime := time.Now()

		fmt.Printf("real-time delta: %s\n", nowRealTime.Sub(nowUTC))
	}

	if result.OutOfRangeAnswer {
		fmt.Fprintf(os.Stderr, "One or more of the answers was significantly out of range.\n")
	}

	trimChain(chain, maxChainSize)

	fmt.Println(chain)
}
