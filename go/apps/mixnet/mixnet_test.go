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
	"bytes"
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
var routerAddr string = "localhost:7007"
var dstAddr string = "localhost:7009"

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
	router, err := NewRouterContext(configPath, network, routerAddr, &id, st)
	if err != nil {
		return nil, nil, err
	}

	// Create a proxy context. This just loads the domain.
	proxy, err := NewProxyContext(configPath)
	if err != nil {
		router.Close()
		return nil, nil, err
	}

	return router, proxy, nil
}

type testResult struct {
	err error
	msg []byte
}

// Router accepts a connection from a proxy and reads a cell.
func runRouterReadCell(router *RouterContext, ch chan<- testResult) {
	c, err := router.AcceptProxy()
	if err != nil {
		ch <- testResult{err, []byte{}}
		return
	}

	cell := make([]byte, CellBytes)
	if _, err := c.Read(cell); err != nil {
		ch <- testResult{err, unpadCell(cell)}
	} else {
		ch <- testResult{nil, unpadCell(cell)}
	}
}

// Proxy dials a router and sends a cell.
func runProxyWriteCell(proxy *ProxyContext, msg []byte) error {
	c, err := proxy.DialRouter(network, routerAddr)
	if err != nil {
		return err
	}
	defer c.Close()

	if _, err := c.Write(padCell(msg)); err != nil {
		return err
	}

	return nil
}

// Router accepts a connection from a proxy and handles two requests.
func runRouterHandleProxy(router *RouterContext, ch chan<- testResult) {
	c, err := router.AcceptProxy()
	if err != nil {
		ch <- testResult{err, []byte{}}
		return
	}

	// Create circuit.
	if err = router.HandleProxy(c); err != nil {
		ch <- testResult{err, []byte{}}
		return
	}

	// Receive message.
	if err = router.HandleProxy(c); err != nil {
		ch <- testResult{err, []byte{}}
		return
	}

	ch <- testResult{nil, router.msgBuffer}
}

// Proxy dials a router, creates a circuit, and sends a message over
// the circuit.
func runProxyRelay(proxy *ProxyContext, msg []byte) error {
	c, err := proxy.DialRouter(network, routerAddr)
	if err != nil {
		return err
	}
	defer c.Close()

	if _, err = proxy.CreateCircuit(c, []string{dstAddr}); err != nil {
		return err
	}

	if _, err = proxy.SendMessage(c, msg); err != nil {
		return err
	}

	return nil
}

// Test padding.
func TestPadding(t *testing.T) {
	msg := make([]byte, CellBytes+7)
	for i := 0; i < CellBytes+7; i++ {
		msg[i] = byte(i % 256)
	}

	if bytes.Compare(msg[:CellBytes], unpadCell(padCell(msg[:CellBytes]))) != 0 {
		t.Error("failed to pad message the length of a cell")
	}

	if bytes.Compare(msg[:CellBytes-31], unpadCell(padCell(msg[:CellBytes-31]))) != 0 {
		t.Error("failed to pad a short message")
	}

	if bytes.Compare(msg, unpadCell(padCell(msg))) != 0 {
		t.Error("failed to pad a longer message")
	}
}

// Test connection set up.
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

	c, err := proxy.DialRouter(network, routerAddr)
	if err != nil {
		router.Close()
		t.Fatal(err)
	}
	defer c.Close()

	<-ch
}

// Test sending a cell.
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

// Test setting up a circuit and relaying a message.
func TestProxyRouterRelay(t *testing.T) {
	router, proxy, err := makeContext()
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	ch := make(chan testResult)

	msg := make([]byte, (CellBytes*5)+237)
	for i := 0; i < len(msg); i++ {
		msg[i] = byte(i % 256)
	}

	// Short message.
	go runRouterHandleProxy(router, ch)
	if err = runProxyRelay(proxy, msg[:37]); err != nil {
		t.Error(err)
	}
	res := <-ch
	if res.err != nil {
		t.Error(res.err)
	} else if bytes.Compare(res.msg, msg[:37]) != 0 {
		t.Error("Short message, server got:", res.msg)
	}

	// Long message.
	go runRouterHandleProxy(router, ch)
	if err = runProxyRelay(proxy, msg); err != nil {
		t.Error(err)
	}
	res = <-ch
	if res.err != nil {
		t.Error(res.err)
	} else if bytes.Compare(res.msg, msg) != 0 {
		t.Error("Long message, server got:", res.msg)
	}
}
