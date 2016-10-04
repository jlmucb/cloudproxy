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
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
)

var password = make([]byte, 32)
var network = "tcp"
var localAddr = "127.0.0.1:0"
var timeout, _ = time.ParseDuration("1s")
var configDirName = "mixnet_test_domain"

var id = pkix.Name{
	Organization: []string{"Mixnet tester"},
}

// genHostname() generates a random hostname.
func genHostname() string {
	rb := make([]byte, 16)
	rand.Read(rb)
	return base64.URLEncoding.EncodeToString(rb)
}

func makeTrivialDomain(configDir string) (*tao.Domain, error) {
	var policyDomainConfig tao.DomainConfig
	policyDomainConfig.SetDefaults()
	policyDomainConfig.DomainInfo.GuardType = proto.String("AllowAll")
	configPath := path.Join(configDir, "tao.config")
	return tao.CreateDomain(policyDomainConfig, configPath, password)
}

func makeContext(batchSize int) (*RouterContext, *ProxyContext, *tao.Domain, error) {
	tempDir, err := ioutil.TempDir("", configDirName)
	if err != nil {
		return nil, nil, nil, err
	}
	// Create a domain with a LiberalGuard.
	d, err := makeTrivialDomain(tempDir)
	if err != nil {
		return nil, nil, nil, err
	}

	router, err := makeRouterContext(tempDir, localAddr, batchSize, d)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create a proxy context. This just loads the domain.
	proxy, err := makeProxyContext(localAddr, d)
	if err != nil {
		router.Close()
		return nil, nil, nil, err
	}

	return router, proxy, d, nil
}

func makeRouterContext(dir, rAddr string, batchSize int, domain *tao.Domain) (*RouterContext, error) {
	// Create a SoftTao from the domain.
	st, err := tao.NewSoftTao(dir, password)
	if err != nil {
		return nil, err
	}

	// Create router context. This loads the domain and binds a
	// socket and an anddress.
	router, err := NewRouterContext(domain.ConfigPath, network, rAddr,
		batchSize, timeout, &id, st)
	if err != nil {
		return nil, err
	}
	return router, nil
}

func makeProxyContext(proxyAddr string, domain *tao.Domain) (*ProxyContext, error) {
	// Create a proxy context. This just loads the domain.
	proxy, err := NewProxyContext(domain.ConfigPath, network, proxyAddr, timeout)
	if err != nil {
		return nil, err
	}

	return proxy, nil
}

type testResult struct {
	err error
	msg []byte
}

// Router accepts a connection from a proxy and reads a cell.
func runRouterReadCell(router *RouterContext, ch chan<- testResult) {
	c, err := router.Accept()
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

// Proxy dials a router and sends a cell.
func runProxyWriteCell(proxy *ProxyContext, addr string, msg []byte) error {
	c, err := proxy.DialRouter(network, addr)
	if err != nil {
		return err
	}

	if _, err := c.Write(msg); err != nil {
		return err
	}

	return nil
}

// Router accepts a connection from a proxy and handles a number of requests.
func runRouterHandleOneProxy(router *RouterContext, requestCount int, ch chan<- testResult) {
	_, err := router.Accept()
	if err != nil {
		ch <- testResult{err, []byte{}}
		return
	}

	for i := 0; i < requestCount; i++ {
		if err = <-router.errs; err != nil {
			ch <- testResult{err, nil}
		}
	}

	ch <- testResult{nil, nil}
}

// Router accepts a connection from a router and handles a number of requests.
func runRouterHandleOneRouter(router *RouterContext, requestCount int, ch chan<- testResult) {
	_, err := router.Accept()
	if err != nil {
		ch <- testResult{err, []byte{}}
		return
	}

	for i := 0; i < requestCount; i++ {
		if err = <-router.errs; err != nil {
			ch <- testResult{err, nil}
		}
	}

	ch <- testResult{nil, nil}
}

// Router accepts a connection from a proxy with multiple circuits
func runRouterHandleOneProxyMultCircuits(router *RouterContext, numCircuits int, requestCounts []int, ch chan<- testResult) {
	_, err := router.Accept()
	if err != nil {
		ch <- testResult{err, []byte{}}
		return
	}

	for circ := 0; circ < numCircuits; circ++ {
		for i := 0; i < requestCounts[circ]; i++ {
			if err = <-router.errs; err != nil {
				ch <- testResult{err, nil}
			}
		}
	}
	ch <- testResult{nil, nil}
}

func runRouterHandleProxy(router *RouterContext, clientCt, requestCt int, ch chan<- testResult) {
	for i := 0; i < clientCt; i++ {
		_, err := router.Accept()
		if err != nil {
			ch <- testResult{err, []byte{}}
			return
		}
	}

	for i := 0; i < clientCt*requestCt; i++ {
		if err := <-router.errs; err != nil {
			ch <- testResult{err, nil}
		}
	}

	ch <- testResult{nil, nil}
}

// Router accepts a connection from a router and handles a number of requests.
func runRouterHandleRouters(router *RouterContext, routerCt, requestCount int, ch chan<- testResult) {
	for i := 0; i < routerCt; i++ {
		_, err := router.Accept()
		if err != nil {
			ch <- testResult{err, []byte{}}
			return
		}
	}

	for i := 0; i < routerCt*requestCount; i++ {
		if err := <-router.errs; err != nil {
			ch <- testResult{err, nil}
		}
	}

	ch <- testResult{nil, nil}
}

// Proxy dials a router, creates a circuit, and sends a message over
// the circuit.
func runProxySendMessage(proxy *ProxyContext, rAddr, dAddr string, msg []byte) ([]byte, error) {
	id, err := proxy.CreateCircuit([]string{rAddr, dAddr})
	if err != nil {
		return nil, err
	}

	c := proxy.circuits[id]

	if err = c.SendMessage(id, msg); err != nil {
		return nil, err
	}

	// dummyServer receives one message and replies. Without this line,
	// the router will report a broken pipe.
	msg, err = c.ReceiveMessage(id)
	return msg, err
}

// Test connection set up.
func TestProxyRouterConnect(t *testing.T) {
	router, proxy, domain, err := makeContext(1)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	defer proxy.Close()
	defer os.RemoveAll(path.Base(domain.ConfigPath))
	routerAddr := router.listener.Addr().String()

	// Wait for a connection from the proxy.
	ch := make(chan bool)
	go func(ch chan<- bool) {
		router.Accept()
		ch <- true
	}(ch)

	_, err = proxy.DialRouter(network, routerAddr)
	if err != nil {
		t.Error(err)
	}

	<-ch
}

// Test CREATE and DESTROY.
func TestCreateDestroy(t *testing.T) {
	router, proxy, domain, err := makeContext(1)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	defer proxy.Close()
	defer os.RemoveAll(path.Base(domain.ConfigPath))
	rAddr := router.listener.Addr().String()

	// The address doesn't matter here because no packets will be sent on
	// the established circuit.
	fakeAddr := "127.0.0.1:0"
	ch := make(chan testResult)
	go runRouterHandleOneProxy(router, 2, ch)

	id, err := proxy.CreateCircuit([]string{rAddr, fakeAddr})
	if err != nil {
		t.Error("Error creating circuit:", err)
	}

	if len(router.nextIds) != 1 {
		t.Error("Failed to establish circuit:", len(router.nextIds))
	}

	if err = proxy.DestroyCircuit(id); err != nil {
		t.Error("Error destroying circuit:", err)
	}

	res := <-ch
	if res.err != nil {
		t.Error("Unexpected router error:", res.err)
	}

	if len(router.nextIds) != 0 {
		t.Error("Expecting 0 circuits, but have", len(router.nextIds))
	}
}

func TestCreateDestroyMultiHop(t *testing.T) {
	router1, proxy, domain, err := makeContext(1)
	if err != nil {
		t.Fatal(err)
	}
	tempDir, err := ioutil.TempDir("", configDirName)
	if err != nil {
		t.Fatal(err)
	}
	router2, err := makeRouterContext(tempDir, localAddr, 1, domain)
	if err != nil {
		t.Fatal(err)
	}
	router3, err := makeRouterContext(tempDir, localAddr, 1, domain)
	if err != nil {
		t.Fatal(err)
	}
	defer router1.Close()
	defer router2.Close()
	defer router3.Close()
	defer proxy.Close()
	defer os.RemoveAll(path.Base(domain.ConfigPath))
	rAddr1 := router1.listener.Addr().String()
	rAddr2 := router2.listener.Addr().String()
	rAddr3 := router3.listener.Addr().String()

	// The address doesn't matter here because no packets will be sent on
	// the established circuit.
	fakeAddr := "127.0.0.1:0"
	ch1 := make(chan testResult)
	ch2 := make(chan testResult)
	ch3 := make(chan testResult)
	go runRouterHandleOneProxy(router1, 2*2, ch1)
	go runRouterHandleOneRouter(router2, 2*2, ch2)
	go runRouterHandleOneRouter(router3, 2, ch3)

	id, err := proxy.CreateCircuit([]string{rAddr1, rAddr2, rAddr3, fakeAddr})
	if err != nil {
		t.Error(err)
	}

	if len(router1.nextIds) != 1 || len(router2.nextIds) != 1 || len(router3.nextIds) != 1 {
		t.Error("Expecting 0 connections, but have",
			len(router1.nextIds), len(router2.nextIds), len(router3.nextIds))
	}

	if err = proxy.DestroyCircuit(id); err != nil {
		t.Error("Could not destroy circuit:", err)
	}

	res := <-ch1
	if res.err != nil {
		t.Error("Unexpected router error:", res.err)
	}
	res = <-ch2
	if res.err != nil {
		t.Error("Unexpected router error:", res.err)
	}
	res = <-ch3
	if res.err != nil {
		t.Error("Unexpected router error:", res.err)
	}

	if len(router1.nextIds) != 0 || len(router2.nextIds) != 0 || len(router3.nextIds) != 0 {
		t.Error("Expecting 0 connections, but have",
			len(router1.nextIds), len(router2.nextIds), len(router3.nextIds))
	}
}

// Test multiplexing for proxy
func TestMultiplexProxyCircuit(t *testing.T) {
	router, proxy, domain, err := makeContext(1)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	defer proxy.Close()
	defer os.RemoveAll(path.Base(domain.ConfigPath))
	rAddr := router.listener.Addr().String()

	// The address doesn't matter here because no packets will be sent on
	// the established circuit.
	ch := make(chan testResult)
	clientCt := 2
	numReqs := make([]int, clientCt)
	fakeAddrs := make([]string, clientCt)
	ids := make([]uint64, clientCt)
	for i := range numReqs {
		numReqs[i] = 2
		fakeAddrs[i] = fmt.Sprintf("127.0.0.1:%d", -i)
	}
	go runRouterHandleOneProxyMultCircuits(router, clientCt, numReqs, ch)

	for i := range numReqs {
		ids[i], err = proxy.CreateCircuit([]string{rAddr, fakeAddrs[i]})
		if err != nil {
			t.Error("Couldn't create circuit:", err)
		}
	}

	unique := make(map[*Conn]bool)
	for _, conn := range proxy.circuits {
		unique[conn] = true
	}
	if len(unique) != 1 {
		t.Error(errors.New("Should only have one connection"))
	}

	for i := range numReqs {
		err = proxy.DestroyCircuit(ids[i])
		if err != nil {
			t.Error("Couldn't destroy circuit:", err)
		}
	}
	res := <-ch
	if res.err != nil {
		t.Error("Unexpected router error:", res.err)
	}
}

// Test sending a cell.
func TestProxyRouterCell(t *testing.T) {
	router, proxy, domain, err := makeContext(1)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	defer proxy.Close()
	defer os.RemoveAll(path.Base(domain.ConfigPath))
	ch := make(chan testResult)

	cell := make([]byte, CellBytes+1)
	for i := 0; i < len(cell); i++ {
		cell[i] = byte(i)
	}

	// This cell is just right.
	go runRouterReadCell(router, ch)
	if err = runProxyWriteCell(proxy, router.listener.Addr().String(), cell[:CellBytes]); err != nil {
		t.Error(err)
	}
	res := <-ch
	if res.err != nil && res.err != io.EOF {
		t.Error(res.err)
	} else if bytes.Compare(res.msg, cell[:CellBytes]) != 0 {
		t.Errorf("Server got: %s", res.msg)
	}

	// This cell is too big.
	go runRouterReadCell(router, ch)
	if err = runProxyWriteCell(proxy, router.listener.Addr().String(), cell); err != errCellLength {
		t.Error("runProxyWriteCell(): should have returned errCellLength")
	}
	res = <-ch
	if err := res.err.(net.Error); !err.Timeout() {
		t.Error("runRouterReadCell(): should have timed out")
	}
}

// Test setting up a circuit and relay a message to destination. Try
// messages of various lengths.
func TestProxyRouterRelay(t *testing.T) {
	router, proxy, domain, err := makeContext(1)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	defer proxy.Close()
	defer os.RemoveAll(path.Base(domain.ConfigPath))
	routerCh := make(chan testResult)
	dstCh := make(chan testResult)
	dstAddrCh := make(chan string)

	// Create a long message.
	msg := make([]byte, (CellBytes*5)+237)
	for i := 0; i < len(msg); i++ {
		msg[i] = byte(i)
	}
	var res testResult

	trials := []int{
		37, // A short message
		CellBytes - (BODY + LEN_SIZE), // A cell
		len(msg),                      // A long message
	}

	go runDummyServer(len(trials), 1, dstCh, dstAddrCh)
	dstAddr := <-dstAddrCh
	rAddr := router.listener.Addr().String()

	// First two messages fits in one cell, the last one is over multiple cells
	// Funky counting, since the cells contain some meta data..
	longReqCt := 1 + ((len(msg)-(CellBytes-(BODY+8)))/(CellBytes-BODY) + 1)
	reqCts := []int{2, 2, longReqCt + 1}

	go runRouterHandleOneProxyMultCircuits(router, len(trials), reqCts, routerCh)

	for _, l := range trials {
		reply, err := runProxySendMessage(proxy, rAddr, dstAddr, msg[:l])
		if err != nil {
			t.Errorf("relay (length=%d): %s", l, err)
		}

		res = <-dstCh
		if res.err != nil {
			t.Error(res.err)
		} else if bytes.Compare(reply, msg[:l]) != 0 {
			t.Errorf("relay (length=%d): received: %v", l, reply)
			t.Errorf("relay (length=%d): sent: %x", l, msg[:l])
		}
	}
	res = <-routerCh
	if res.err != nil {
		t.Error("relay error:", res.err)
	}
}

// Test sending malformed messages from the proxy to the router.
func TestMaliciousProxyRouterRelay(t *testing.T) {
	router, proxy, domain, err := makeContext(1)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	defer proxy.Close()
	defer os.RemoveAll(path.Base(domain.ConfigPath))
	routerAddr := router.listener.Addr().String()
	ch := make(chan testResult)

	go runRouterHandleOneProxy(router, 5, ch)
	fakeAddr := "127.0.0.1:0"
	id, err := proxy.CreateCircuit([]string{routerAddr, fakeAddr})
	if err != nil {
		t.Error(err)
	}
	cell := make([]byte, CellBytes)
	binary.LittleEndian.PutUint64(cell[ID:], id)
	c := proxy.circuits[id]

	// Unrecognized cell type.
	cell[TYPE] = 0xff
	if _, err = c.Write(cell); err != nil {
		t.Error(err)
	}
	_, err = c.ReceiveMessage(id)
	if err == nil {
		t.Error("ReceiveMessage incorrectly succeeded")
	}

	// Message too long.
	cell[TYPE] = msgCell
	binary.LittleEndian.PutUint64(cell[BODY:], uint64(MaxMsgBytes+1))
	if _, err := c.Write(cell); err != nil {
		t.Error(err)
	}
	_, err = c.ReceiveMessage(id)
	if err == nil {
		t.Error("ReceiveMessage incorrectly succeeded")
	}

	if err = c.SendMessage(id, []byte("Are you there?")); err != nil {
		t.Error(err)
	}
	_, err = c.ReceiveMessage(id)
	if err == nil {
		t.Error("Receive message incorrectly succeeded")
	}
	err = proxy.DestroyCircuit(id)
	if err != nil {
		t.Error(err)
	}

	res := <-ch
	if res.err != nil {
		t.Error("Not expecting any router errors, but got", res.err)
	}
}

// Test timeout on CreateMessage().
func TestCreateTimeout(t *testing.T) {
	router, proxy, domain, err := makeContext(2)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	defer proxy.Close()
	defer os.RemoveAll(path.Base(domain.ConfigPath))
	routerAddr := router.listener.Addr().String()
	ch := make(chan testResult)

	// The proxy should get a timeout if it's the only connecting client.
	go runRouterHandleProxy(router, 1, 1, ch)
	hostAddr := genHostname() + ":80"
	_, err = proxy.CreateCircuit([]string{routerAddr, hostAddr})
	if err == nil {
		t.Errorf("proxy.CreateCircuit(%s, %s) incorrectly succeeded when it should have timed out", routerAddr, hostAddr)
	}
	res := <-ch
	if res.err != nil {
		t.Error(res.err)
	}
}

// Test timeout on ReceiveMessage().
func TestSendMessageTimeout(t *testing.T) {
	router, proxy, domain, err := makeContext(2)
	if err != nil {
		t.Fatal(err)
	}
	proxy2, err := makeProxyContext(localAddr, domain)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	defer proxy.Close()
	defer proxy2.Close()
	defer os.RemoveAll(path.Base(domain.ConfigPath))
	routerAddr := router.listener.Addr().String()
	ch := make(chan testResult)
	done := make(chan bool)

	go runRouterHandleProxy(router, 2, 2, ch)

	// Proxy 1 creates a circuit, sends a message and awaits a reply.
	go func() {
		id, err := proxy.CreateCircuit([]string{routerAddr, genHostname() + ":80"})
		if err != nil {
			t.Error(err)
		}
		c := proxy.circuits[id]
		if err = c.SendMessage(id, []byte("hello")); err != nil {
			t.Error(err)
		}
		_, err = c.ReceiveMessage(id)
		if e, ok := err.(net.Error); !(ok && e.Timeout()) {
			t.Error("receiveMessage should have timed out")
		}
		done <- true
	}()

	// Proxy 2 just creates a circuit.
	go func() {
		_, err = proxy2.CreateCircuit([]string{routerAddr, genHostname() + ":80"})
		if err != nil {
			t.Error(err)
		}
		done <- true
	}()
	<-done
	<-done
}

// Test mixnet end-to-end with many clients. Proxy a protocol through mixnet.
// The client sends the server a message and the server echoes it back.
func TestMixnetSingleHop(t *testing.T) {
	clientCt := 10
	router, proxy, domain, err := makeContext(clientCt)
	if err != nil {
		t.Fatal(err)
	}
	proxy.Close()
	defer router.Close()
	defer os.RemoveAll(path.Base(domain.ConfigPath))
	routerAddr := router.listener.Addr().String()

	var res testResult
	clientCh := make(chan testResult, clientCt)
	proxyCh := make(chan testResult, clientCt)
	routerCh := make(chan testResult)
	dstCh := make(chan testResult, clientCt)
	dstAddrCh := make(chan string)

	go runRouterHandleProxy(router, clientCt, 3, routerCh)
	go runDummyServer(clientCt, 1, dstCh, dstAddrCh)
	dstAddr := <-dstAddrCh

	for i := 0; i < clientCt; i++ {
		go func(pid int, ch chan<- testResult) {
			pa := "127.0.0.1:0"
			proxy, err := makeProxyContext(pa, domain)
			if err != nil {
				ch <- testResult{err, nil}
				return
			}
			defer proxy.Close()
			proxyAddr := proxy.listener.Addr().String()
			go runSocksServerOne(proxy, []string{routerAddr}, proxyCh)

			msg := []byte(fmt.Sprintf("Hello, my name is %d", pid))
			ch <- runSocksClient(proxyAddr, dstAddr, msg)
		}(i, clientCh)
	}

	// Wait for clients to finish.
	for i := 0; i < clientCt; i++ {
		res = <-clientCh
		if res.err != nil {
			t.Error(res.err)
		} else {
			t.Log("client got:", string(res.msg))
		}
	}

	// Wait for proxies to finish.
	for i := 0; i < clientCt; i++ {
		res = <-proxyCh
		if res.err != nil {
			t.Error(res.err)
		}
	}

	// Wait for server to finish.
	for i := 0; i < clientCt; i++ {
		res = <-dstCh
		if res.err != nil {
			t.Error(res.err)
		}
	}

	// Wait for router to finish.
	res = <-routerCh
	if res.err != nil {
		t.Error("Unexpected router error:", res.err)
	}
}

// Test mixnet end-to-end with many clients and two routers.
func TestMixnetMultiHop(t *testing.T) {
	clientCt := 10
	router, proxy, domain, err := makeContext(clientCt)
	if err != nil {
		t.Fatal(err)
	}
	tempDir, err := ioutil.TempDir("", configDirName)
	if err != nil {
		t.Fatal(err)
	}
	router2, err := makeRouterContext(tempDir, localAddr, 1, domain)
	if err != nil {
		t.Fatal(err)
	}
	router3, err := makeRouterContext(tempDir, localAddr, 1, domain)
	if err != nil {
		t.Fatal(err)
	}
	proxy.Close()
	defer router.Close()
	defer os.RemoveAll(path.Base(domain.ConfigPath))
	routerAddr := router.listener.Addr().String()
	routerAddr2 := router2.listener.Addr().String()
	routerAddr3 := router3.listener.Addr().String()

	var res testResult
	clientCh := make(chan testResult, clientCt)
	proxyCh := make(chan testResult, clientCt)
	routerCh := make(chan testResult)
	routerCh2 := make(chan testResult)
	dstCh := make(chan testResult, clientCt)
	dstAddrCh := make(chan string)

	go runRouterHandleProxy(router, clientCt, 3*2, routerCh)
	go runRouterHandleOneRouter(router2, clientCt*3*2, routerCh2)
	go runRouterHandleOneRouter(router3, clientCt*3, routerCh2)
	go runDummyServer(clientCt, 1, dstCh, dstAddrCh)
	dstAddr := <-dstAddrCh

	for i := 0; i < clientCt; i++ {
		go func(pid int, ch chan<- testResult) {
			pa := "127.0.0.1:0"
			proxy, err := makeProxyContext(pa, domain)
			if err != nil {
				ch <- testResult{err, nil}
				return
			}
			defer proxy.Close()
			proxyAddr := proxy.listener.Addr().String()
			go runSocksServerOne(proxy, []string{routerAddr, routerAddr2, routerAddr3}, proxyCh)

			msg := []byte(fmt.Sprintf("Hello, my name is %d", pid))
			ch <- runSocksClient(proxyAddr, dstAddr, msg)
		}(i, clientCh)
	}

	// Wait for clients to finish.
	for i := 0; i < clientCt; i++ {
		res = <-clientCh
		if res.err != nil {
			t.Error(res.err)
		} else {
			t.Log("client got:", string(res.msg))
		}
	}

	// Wait for proxies to finish.
	for i := 0; i < clientCt; i++ {
		res = <-proxyCh
		if res.err != nil {
			t.Error(res.err)
		}
	}

	// Wait for server to finish.
	for i := 0; i < clientCt; i++ {
		res = <-dstCh
		if res.err != nil {
			t.Error(res.err)
		}
	}

	// Wait for router to finish.
	res = <-routerCh
	if res.err != nil {
		t.Error("Unexpected router error:", res.err)
	}

	// Wait for router to finish.
	res = <-routerCh2
	if res.err != nil {
		t.Error("Unexpected router error:", res.err)
	}
}

// Test mixnets with multiple paths, mixing with each other
// Current test only supports even and same number of clients per router
func TestMixnetMultiPath(t *testing.T) {
	clientCt := 20
	numPaths := 2
	perPath := clientCt / numPaths
	pathLen := 3
	routerCt := pathLen * numPaths
	routers := make([]*RouterContext, routerCt)
	routerAddrs := make([]string, routerCt)
	router, proxy, domain, err := makeContext(perPath)
	if err != nil {
		t.Fatal(err)
	}
	routerChs := make([]chan testResult, routerCt)
	tempDir, err := ioutil.TempDir("", configDirName)
	if err != nil {
		t.Fatal(err)
	}
	for i := range routers {
		if i == 0 {
			routers[i] = router
		} else {
			routers[i], err = makeRouterContext(tempDir, localAddr, perPath, domain)
			if err != nil {
				t.Fatal(err)
			}
		}
		defer routers[i].Close()
		routerChs[i] = make(chan testResult)
		if i%3 == 0 { // entry
			routerAddrs[i] = routers[i].listener.Addr().String()
			go runRouterHandleProxy(routers[i], perPath, 3*2, routerChs[i])
		} else {
			routerAddrs[i] = routers[i].listener.Addr().String()
			if i%3 == 1 { // middle
				go runRouterHandleRouters(routers[i], numPaths, perPath*3*2/numPaths, routerChs[i])
			} else { // exit
				go runRouterHandleRouters(routers[i], numPaths, perPath*3/numPaths, routerChs[i])
			}
		}
	}
	proxy.Close()
	defer os.RemoveAll(path.Base(domain.ConfigPath))

	var res testResult
	clientCh := make(chan testResult, clientCt)
	proxyCh := make(chan testResult, clientCt)
	dstCh := make(chan testResult, clientCt)
	dstAddrCh := make(chan string)

	go runDummyServer(clientCt, 1, dstCh, dstAddrCh)
	dstAddr := <-dstAddrCh
	for i := 0; i < clientCt; i++ {
		go func(pid int, ch chan<- testResult) {
			pa := "127.0.0.1:0"
			proxy, err := makeProxyContext(pa, domain)
			if err != nil {
				ch <- testResult{err, nil}
				return
			}
			defer proxy.Close()
			proxyAddr := proxy.listener.Addr().String()
			circuit := make([]string, pathLen)
			if pid%2 == 0 {
				copy(circuit, routerAddrs[:3])
				if pid%4 == 2 {
					circuit[1] = routerAddrs[4]
				}
			} else {
				copy(circuit, routerAddrs[3:])
				if pid%4 == 3 {
					circuit[1] = routerAddrs[1]
				} else {
				}
			}
			go runSocksServerOne(proxy, circuit, proxyCh)

			msg := []byte(fmt.Sprintf("Hello, my name is %d", pid))
			ch <- runSocksClient(proxyAddr, dstAddr, msg)
		}(i, clientCh)
	}

	// Wait for clients to finish.
	for i := 0; i < clientCt; i++ {
		res = <-clientCh
		if res.err != nil {
			t.Error(res.err)
		} else {
			t.Log("client got:", string(res.msg))
		}
	}

	// Wait for proxies to finish.
	for i := 0; i < clientCt; i++ {
		res = <-proxyCh
		if res.err != nil {
			t.Error(res.err)
		}
	}

	// Wait for server to finish.
	for i := 0; i < clientCt; i++ {
		res = <-dstCh
		if res.err != nil {
			t.Error(res.err)
		}
	}

	// Wait for router to finish.
	for i := range routers {
		res = <-routerChs[i]
		if res.err != nil {
			t.Fatal(i, "Unexpected router error:", res.err)
		}
	}
}
