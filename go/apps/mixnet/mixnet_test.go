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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"sync"
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

func makeContext(batchSize int) (*RouterContext, *ProxyContext, *DirectoryContext, *tao.Domain, error) {
	tempDir, err := ioutil.TempDir("", configDirName)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// Create a domain with a LiberalGuard.
	d, err := makeTrivialDomain(tempDir)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	router, err := makeRouterContext(tempDir, localAddr, batchSize, d)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Create a proxy context. This just loads the domain.
	proxy, err := makeProxyContext(localAddr, d)
	if err != nil {
		router.Close()
		return nil, nil, nil, nil, err
	}

	directory, err := makeDirectorycontext(tempDir, localAddr, d)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return router, proxy, directory, d, nil
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
	// Because we are auto assigning ports, explicitly set the addr here
	router.addr = router.listener.Addr().String()
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

func makeDirectorycontext(dir, addr string, domain *tao.Domain) (*DirectoryContext, error) {
	// Create a SoftTao from the domain.
	st, err := tao.NewSoftTao(dir, password)
	if err != nil {
		return nil, err
	}

	directory, err := NewDirectoryContext(domain.ConfigPath, network, addr, timeout, &id, st)
	if err != nil {
		return nil, err
	}
	return directory, nil
}

type testResult struct {
	err error
	msg []byte
}

func setupDirectory(routers []*RouterContext, directory *DirectoryContext) {
	go func() {
		for i := 0; i < len(routers)*2; i++ {
			directory.Accept()
		}
	}()

	for _, router := range routers {
		router.addr = router.listener.Addr().String()
		err := router.Register(directory.listener.Addr().String())
		if err != nil {
			log.Fatal(err)
		}
	}
	for _, router := range routers {
		err := router.GetDirectory(directory.listener.Addr().String())
		if err != nil {
			log.Fatal(err)
		}
	}
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
func runRouterHandleOneConn(router *RouterContext, ch chan<- testResult) {
	_, err := router.Accept()
	if err != nil {
		ch <- testResult{err, []byte{}}
		return
	}

	for {
		if err = <-router.errs; err != nil {
			ch <- testResult{err, nil}
		}
	}
}

// Router accepts a connection from a proxy with multiple circuits
func runRouterHandleOneConnMultCircuits(router *RouterContext, ch chan<- testResult) {
	_, err := router.Accept()
	if err != nil {
		ch <- testResult{err, []byte{}}
		return
	}

	for {
		if err = <-router.errs; err != nil {
			ch <- testResult{err, nil}
		}
	}
}

func runRouterHandleConns(router *RouterContext, connCt int, ch chan<- testResult) {
	for i := 0; i < connCt; i++ {
		_, err := router.Accept()
		if err != nil {
			ch <- testResult{err, []byte{}}
			return
		}
	}

	for {
		if err := <-router.errs; err != nil {
			ch <- testResult{err, nil}
		}
	}
}

// Proxy dials a router, creates a circuit, and sends a message over
// the circuit.
func runProxySendMessage(proxy *ProxyContext, rAddr, dAddr string, msg []byte, exitKey *[32]byte) ([]byte, error) {
	circ, _, err := proxy.CreateCircuit([]string{rAddr, dAddr}, exitKey)
	if err != nil {
		return nil, err
	}

	if err = circ.SendMessage(msg); err != nil {
		return nil, err
	}

	// dummyServer receives one message and replies. Without this line,
	// the router will report a broken pipe.
	msg, err = circ.ReceiveMessage()
	return msg, err
}

// A dummy TLS server echoes back client's message.
func runTLSServer(clientCt int, ch chan<- testResult, addr chan<- string) {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	config := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequestClientCert,
	}
	l, err := tls.Listen(network, localAddr, config)
	if err != nil {
		ch <- testResult{err, []byte{}}
		return
	}
	defer l.Close()
	addr <- l.Addr().String()

	for i := 0; i < clientCt; i++ {
		c, err := l.Accept()
		if err != nil {
			ch <- testResult{err, []byte{}}
			return
		}

		go func(c net.Conn, clientNo int) {
			defer c.Close()
			buf := make([]byte, MaxMsgBytes+1)
			for {
				bytes, err := c.Read(buf)
				if err != nil {
					ch <- testResult{err, nil}
				} else {
					_, err := c.Write(buf[:bytes])
					if err != nil {
						ch <- testResult{err, nil}
					} else {
						bufCopy := make([]byte, bytes)
						copy(bufCopy, buf[:bytes])
						ch <- testResult{nil, bufCopy}
					}
				}
			}
		}(c, i)
	}
}

// Test connection set up.
func TestProxyRouterConnect(t *testing.T) {
	router, proxy, _, domain, err := makeContext(1)
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
	router, proxy, directory, domain, err := makeContext(1)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	defer proxy.Close()
	defer os.RemoveAll(path.Base(domain.ConfigPath))
	setupDirectory([]*RouterContext{router}, directory)
	rAddr := router.listener.Addr().String()

	// The address doesn't matter here because no packets will be sent on
	// the established circuit.
	fakeAddr := "127.0.0.1:0"
	ch := make(chan testResult)
	go runRouterHandleOneConn(router, ch)

	_, id, err := proxy.CreateCircuit([]string{rAddr, fakeAddr}, router.publicKey)
	if err != nil {
		t.Error("Error creating circuit:", err)
	}

	if len(router.nextIds) != 1 {
		t.Error("Failed to establish circuit:", len(router.nextIds))
	}

	if err = proxy.DestroyCircuit(id); err != nil {
		t.Error("Error destroying circuit:", err)
	}

	select {
	case res := <-ch:
		if res.err != nil {
			t.Error("Unexpected router error:", res.err)
		}
	default:
	}

	if len(router.nextIds) != 0 {
		t.Error("Expecting 0 circuits, but have", len(router.nextIds))
	}
}

func TestCreateDestroyMultiHop(t *testing.T) {
	router1, proxy, directory, domain, err := makeContext(1)
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
	setupDirectory([]*RouterContext{router1, router2, router3}, directory)
	rAddr1 := router1.listener.Addr().String()
	rAddr2 := router2.listener.Addr().String()
	rAddr3 := router3.listener.Addr().String()

	// The address doesn't matter here because no packets will be sent on
	// the established circuit.
	fakeAddr := "127.0.0.1:0"
	ch1 := make(chan testResult)
	ch2 := make(chan testResult)
	ch3 := make(chan testResult)
	go runRouterHandleOneConn(router1, ch1)
	go runRouterHandleOneConn(router2, ch2)
	go runRouterHandleOneConn(router3, ch3)

	_, id, err := proxy.CreateCircuit([]string{rAddr1, rAddr2, rAddr3, fakeAddr},
		router3.publicKey)
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

	for _, ch := range []chan testResult{ch1, ch2, ch3} {
		select {
		case res := <-ch:
			if res.err != nil {
				t.Error("Unexpected router error:", res.err)
			}
		default:
		}
	}

	if len(router1.nextIds) != 0 || len(router2.nextIds) != 0 || len(router3.nextIds) != 0 {
		t.Error("Expecting 0 connections, but have",
			len(router1.nextIds), len(router2.nextIds), len(router3.nextIds))
	}
}

// Test multiplexing for proxy
func TestMultiplexProxyCircuit(t *testing.T) {
	router, proxy, _, domain, err := makeContext(1)
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
	go runRouterHandleOneConnMultCircuits(router, ch)

	wg := new(sync.WaitGroup)
	for i := range numReqs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var e error
			_, ids[i], e = proxy.CreateCircuit([]string{rAddr, fakeAddrs[i]}, router.publicKey)
			if e != nil {
				t.Error("Couldn't create circuit:", err)
			}
		}(i)
	}
	wg.Wait()

	unique := make(map[*Conn]bool)
	for _, conn := range proxy.circuits {
		unique[conn] = true
	}
	if len(unique) != 1 {
		t.Error(errors.New("Should only have one connection"))
	}

	for i := range numReqs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := proxy.DestroyCircuit(ids[i])
			if err != nil {
				t.Error("Couldn't destroy circuit:", err)
			}
		}(i)
	}
	wg.Wait()
	select {
	case res := <-ch:
		if res.err != nil {
			t.Error("Unexpected router error:", res.err)
		}
	default:
	}
}

// Test sending a cell.
func TestProxyRouterCell(t *testing.T) {
	router, proxy, _, domain, err := makeContext(1)
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
	router, proxy, _, domain, err := makeContext(1)
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
		//CellBytes - (BODY + LEN_SIZE), // A cell
		//len(msg),                      // A long message
	}

	go runDummyServer(len(trials), 1, dstCh, dstAddrCh)
	dstAddr := <-dstAddrCh
	rAddr := router.listener.Addr().String()

	// First two messages fits in one cell, the last one is over multiple cells
	go runRouterHandleOneConnMultCircuits(router, routerCh)

	for _, l := range trials {
		reply, err := runProxySendMessage(proxy, rAddr, dstAddr, msg[:l], router.publicKey)
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

	select {
	case res := <-routerCh:
		if res.err != nil {
			t.Error("Router error:", res.err)
		}
	default:
	}
}

// TODO(kwonalbert): removed malicious tests because they didn't mean much anymore
// with the new exit nodes..

// Test timeout on CreateMessage().
func TestCreateTimeout(t *testing.T) {
	router, proxy, _, domain, err := makeContext(2)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	defer proxy.Close()
	defer os.RemoveAll(path.Base(domain.ConfigPath))
	routerAddr := router.listener.Addr().String()
	ch := make(chan testResult)

	// The proxy should get a timeout if it's the only connecting client.
	go runRouterHandleConns(router, 1, ch)
	hostAddr := genHostname() + ":80"
	_, _, err = proxy.CreateCircuit([]string{routerAddr, hostAddr}, router.publicKey)
	if err == nil {
		t.Errorf("proxy.CreateCircuit(%s, %s) incorrectly succeeded when it should have timed out", routerAddr, hostAddr)
	}

	select {
	case res := <-ch:
		e, _ := res.err.(net.Error)
		if res.err != nil && !e.Timeout() {
			t.Error(res.err)
		}
	default:
	}
}

// Test timeout on ReceiveMessage().
func TestSendMessageTimeout(t *testing.T) {
	router, proxy, _, domain, err := makeContext(2)
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

	go runRouterHandleConns(router, 2, ch)

	// Proxy 1 creates a circuit, sends a message and awaits a reply.
	go func() {
		circ, _, err := proxy.CreateCircuit([]string{routerAddr, genHostname() + ":80"}, router.publicKey)
		if err != nil {
			t.Error(err)
		}
		if err = circ.SendMessage([]byte("hello")); err != nil {
			t.Error(err)
		}
		_, err = circ.ReceiveMessage()
		if e, ok := err.(net.Error); !(ok && e.Timeout()) {
			t.Error("receiveMessage should have timed out")
		}
		done <- true
	}()

	// Proxy 2 just creates a circuit.
	go func() {
		_, _, err = proxy2.CreateCircuit([]string{routerAddr, genHostname() + ":80"}, router.publicKey)
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
	router, proxy, _, domain, err := makeContext(clientCt)
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

	go runRouterHandleConns(router, clientCt, routerCh)
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
			go runSocksServerOne(proxy, []string{routerAddr}, proxyCh, router.publicKey)

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
	select {
	case res := <-routerCh:
		if res.err != nil {
			t.Error("Unexpected router error:", res.err)
		}
	default:
	}
}

// Test routing TLS connection with mixnet
func TestMixnetSingleHopTLS(t *testing.T) {
	clientCt := 4
	router, proxy, _, domain, err := makeContext(clientCt)
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

	go runRouterHandleConns(router, clientCt, routerCh)
	go runTLSServer(clientCt, dstCh, dstAddrCh)
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
			go runSocksServer(proxy, []string{routerAddr}, proxyCh, router.publicKey)

			msg := []byte(fmt.Sprintf("Hello, my name is %d", pid))
			ch <- runTLSClient(proxyAddr, dstAddr, msg)
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
	select {
	case res := <-routerCh:
		if res.err != nil {
			t.Error("Unexpected router error:", res.err)
		}
	default:
	}
}

// Test mixnet end-to-end with many clients and two routers.
func TestMixnetMultiHop(t *testing.T) {
	clientCt := 10
	router, proxy, directory, domain, err := makeContext(clientCt)
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
	setupDirectory([]*RouterContext{router, router2, router3}, directory)
	routerAddr := router.listener.Addr().String()
	routerAddr2 := router2.listener.Addr().String()
	routerAddr3 := router3.listener.Addr().String()

	var res testResult
	clientCh := make(chan testResult, clientCt)
	proxyCh := make(chan testResult, clientCt)
	routerCh := make(chan testResult)
	routerCh2 := make(chan testResult)
	routerCh3 := make(chan testResult)
	dstCh := make(chan testResult, clientCt)
	dstAddrCh := make(chan string)

	go runRouterHandleConns(router, clientCt, routerCh)
	go runRouterHandleOneConn(router2, routerCh2)
	go runRouterHandleOneConn(router3, routerCh3)
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
			go runSocksServerOne(proxy, []string{routerAddr, routerAddr2, routerAddr3}, proxyCh, router3.publicKey)

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

	// Check if routers had any errors
	for _, ch := range []chan testResult{routerCh, routerCh2} {
		select {
		case res := <-ch:
			if res.err != nil {
				t.Error("Unexpected router error:", res.err)
			}
		default:
		}
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
	router, proxy, directory, domain, err := makeContext(perPath)
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
			go runRouterHandleConns(routers[i], perPath, routerChs[i])
		} else {
			routerAddrs[i] = routers[i].listener.Addr().String()
			go runRouterHandleConns(routers[i], numPaths, routerChs[i])
		}
	}
	proxy.Close()
	defer os.RemoveAll(path.Base(domain.ConfigPath))
	setupDirectory(routers, directory)

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
			var exitKey *[32]byte
			if pid%2 == 0 {
				copy(circuit, routerAddrs[:3])
				if pid%4 == 2 {
					circuit[1] = routerAddrs[4]
				}
				exitKey = routers[2].publicKey
			} else {
				copy(circuit, routerAddrs[3:])
				if pid%4 == 3 {
					circuit[1] = routerAddrs[1]
				}
				exitKey = routers[5].publicKey
			}
			go runSocksServerOne(proxy, circuit, proxyCh, exitKey)

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
		select {
		case res = <-routerChs[i]:
			if res.err != nil {
				t.Fatal(i, "Unexpected router error:", res.err)
			}
		default:
		}
	}
}
