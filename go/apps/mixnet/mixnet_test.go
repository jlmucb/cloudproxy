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
	"io"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
)

var password []byte = make([]byte, 32)
var network string = "tcp"
var addr string = "localhost:8125"

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

	// Create a proxy context. This just loads the domain.
	c, err := NewProxyContext(configPath)
	if err != nil {
		hp.Close()
		return nil, nil, err
	}

	return hp, c, nil
}

type testResult struct {
	err error
	msg []byte
}

func runRouterReadCell(router *RouterContext, ch chan<- testResult) {
	c, err := router.AcceptProxy()
	if err != nil {
		ch <- testResult{err, []byte{}}
		return
	}

	cell := make([]byte, CellBytes)
	if _, err := c.Read(cell); err != nil {
		ch <- testResult{err, cell}
	} else {
		ch <- testResult{nil, cell}
	}
}

func runProxyWriteCell(proxy *ProxyContext, msg []byte) error {
	c, err := proxy.DialRouter(network, addr)
	if err != nil {
		return err
	}
	defer c.Close()

	if _, err := c.Write(msg); err != nil {
		return err
	}

	return nil
}

func TestProxyRouterConnect(t *testing.T) {
	router, proxy, err := makeContext()
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()

	// Wait for a connection from the proxy.
	ch := make(chan bool)
	go func(ch chan<- bool) {
		router.AcceptProxy()
		ch <- true
	}(ch)

	c, err := proxy.DialRouter(network, addr)
	if err != nil {
		router.Close()
		t.Fatal(err)
	}
	defer c.Close()

	<-ch
}

func TestProxyRouterCell(t *testing.T) {
	router, proxy, err := makeContext()
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()

	ch := make(chan testResult)

	// Test sending a good cell. Messages where len(msg) <= CellBytes are zero-padded.
	msg1 := []byte("This is a great message.")
	go runRouterReadCell(router, ch)
	if err = runProxyWriteCell(proxy, msg1); err != nil {
		t.Error(err)
	}
	res := <-ch
	if res.err != nil && res.err != io.EOF {
		t.Error(res.err)
	} else if string(msg1) != strings.TrimRight(string(res.msg), "\x00") {
		t.Errorf("Server got \"%s\", sent \"%s\"", string(res.msg), string(msg1))
	} else {
		t.Logf("Server got \"%s\"", string(res.msg))
	}

	// This cell is too big.
	msg2 := make([]byte, CellBytes+1)
	go runRouterReadCell(router, ch)
	if err = runProxyWriteCell(proxy, msg2); err != errCellLength {
		t.Error("runProxyWriteCell(): should have returned errCellLength")
	}
	res = <-ch
	if res.err != io.EOF {
		t.Error("runRouterReadCell(): should have returned EOF.")
	}

}
