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

package time_client

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"path"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
)

var minerCount int = 30
var chainPath string = "/tmp/chain"
var password []byte = make([]byte, 32)
var network string = "tcp"
var addr string = "127.0.0.1:0"
var dbFile string = "/tmp/chain"
var domainDir string = "/tmp/"

var pkixName = pkix.Name{
	Organization: []string{"CloudProxy"},
}

func makeTrivialDomain(configDir string) (*tao.Domain, error) {
	var policyDomainConfig tao.DomainConfig
	policyDomainConfig.SetDefaults()
	policyDomainConfig.DomainInfo.GuardType = proto.String("AllowAll")
	configPath := path.Join(configDir, "tao.config")
	return tao.CreateDomain(policyDomainConfig, configPath, password)
}

func makeMiner(dir string, domain *tao.Domain, id int) (*Miner, error) {
	// Create a SoftTao from the domain.
	st, err := tao.NewSoftTao(dir, password)
	if err != nil {
		return nil, err
	}

	m, err := NewMiner(network, addr, domain.ConfigPath,
		&pkixName, st, fmt.Sprintf("%s%d", dbFile, id))
	if err != nil {
		return nil, err
	}
	m.id = id
	m.difficulty = GRANULARITY * (minerCount * minerCount)
	return m, nil
}

func checkConsensus(miners []*Miner) error {
	size := miners[0].chain.size
	dist := []int{}
	for m := range miners {
		dist = append(dist, miners[m].chain.size)
		if size > miners[m].chain.size {
			size = miners[m].chain.size
		}
	}
	fmt.Printf("Reached consensus on %d blocks.\n", size)
	fmt.Println("Dist:", dist)
	expected := make([][]byte, size)
	for i := 1; i < size; i++ {
		block, err := miners[0].chain.Block(i)
		if err != nil {
			return err
		}
		bb, err := proto.Marshal(block)
		if err != nil {
			return err
		}
		hash := sha256.Sum256(bb)
		expected[i] = hash[:]
	}

	for _, miner := range miners {
		for i := 1; i < size; i++ {
			block, err := miner.chain.Block(i)
			if err != nil {
				return err
			}
			bb, err := proto.Marshal(block)
			if err != nil {
				return err
			}
			hash := sha256.Sum256(bb)
			for h := range hash {
				if hash[h] != expected[i][h] {
					return errors.New("Didn't reach consensus")
				}
			}
		}
	}
	return nil
}

func TestFullyConnected(t *testing.T) {
	domain, err := makeTrivialDomain(domainDir)
	if err != nil {
		log.Fatal(err)
	}

	miners := make([]*Miner, minerCount)
	for m := range miners {
		miners[m], err = makeMiner(domainDir, domain, m)
		if err != nil {
			log.Fatal(err)
		}
		go miners[m].Serve()
	}

	for m := range miners {
		peers := make([]string, len(miners)-1)
		cnt := 0
		for p := range miners {
			if p == m {
				continue
			}
			peers[cnt] = miners[p].listener.Addr().String()
			cnt++
		}
		miners[m].SetPeers(peers)
	}

	for m := range miners {
		go func(m int) {
			err := miners[m].Protocol()
			t.Error(err)
		}(m)
	}
	sleepFor := miners[0].Difficulty()
	time.Sleep(time.Duration(sleepFor) * INCREMENT)

	err = checkConsensus(miners)
	if err != nil {
		t.Error(err)
	}
}
