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
// limitations under the License0.

package mixnet

import (
	"crypto/x509/pkix"
	"os"
	"path"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
)

var password []byte = make([]byte, 32)

var id pkix.Name = pkix.Name{
	Organization: []string{"Mixnet tester"},
}

func makeTrivialDomain(configDir string) (*tao.Domain, error) {
	var policyDomainConfig tao.DomainConfig
	policyDomainConfig.SetDefaults()
	policyDomainConfig.DomainInfo.GuardType = proto.String("AllowAll")
	configPath := path.Join(configDir, "tao.config")
	return tao.CreateDomain(policyDomainConfig, configPath, password)
}

func makeContext() (*RouterContext, *ProxyContext, error) {
	configDir := "/tmp/mixnet_test_domain"
	configPath := path.Join(configDir, "tao.config")
	network := "tcp"
	addr := "localhost:8125"

	// Create a domain with a LiberalGuard.
	_, err := makeTrivialDomain(configDir)
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(configDir)

	// Create a SoftTao from the domain.
	st, err := tao.NewSoftTao(configDir, password)
	if err != nil {
		return nil, nil, err
	}

	// Create router context. This loads the domain and binds a
	// socket and an anddress.
	hp, err := NewRouterContext(configPath, network, addr, &id, st)
	if err != nil {
		return nil, nil, err
	}

	// Wait for a connection from the proxy.
	ch := make(chan bool)
	go func(ch chan<- bool) {
		hp.Listener.Accept()
		ch <- true
	}(ch)

	// Connect to the router, establish a communication channel.
	c, err := NewProxyContext(configPath, network, addr)
	if err != nil {
		hp.Close()
		return nil, nil, err
	}

	<-ch
	return hp, c, nil
}

func TestProxyRouterConnect(t *testing.T) {
	hp, c, err := makeContext()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer hp.Close()
}
