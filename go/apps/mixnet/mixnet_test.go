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
	"fmt"
	"io"
	"io/ioutil"
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

	// Create a SoftTao from the domain.
	st, err := tao.NewSoftTao(tempDir, password)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create router context. This loads the domain and binds a
	// socket and an anddress.
	router, err := NewRouterContext(d.ConfigPath, network, localAddr,
		batchSize, timeout, &id, st)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create a proxy context. This just loads the domain.
	proxy, err := NewProxyContext(d.ConfigPath, network, localAddr, timeout)
	if err != nil {
		router.Close()
		return nil, nil, nil, err
	}

	return router, proxy, d, nil
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
	c, err := router.AcceptProxy()
	if err != nil {
		ch <- testResult{err, []byte{}}
		return
	}
	defer c.Close()

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
	defer c.Close()

	if _, err := c.Write(msg); err != nil {
		return err
	}

	return nil
}

// Router accepts a connection from a proxy and handles a number of
// requests.
func runRouterHandleOneProxy(router *RouterContext, requestCount int, ch chan<- testResult) {
	c, err := router.AcceptProxy()
	if err != nil {
		ch <- testResult{err, []byte{}}
		return
	}
	defer c.Close()

	for i := 0; i < requestCount; i++ {
		if err = router.HandleConn(c); err != nil {
			ch <- testResult{err, nil}
			return
		}
	}

	ch <- testResult{nil, nil}
}

func runRouterHandleProxy(router *RouterContext, clientCt, requestCt int, ch chan<- testResult) {
	done := make(chan bool)

	for i := 0; i < clientCt; i++ {
		c, err := router.AcceptProxy()
		if err != nil {
			ch <- testResult{err, []byte{}}
			return
		}
		defer c.Close()

		go func(c *Conn) {
			defer func() { done <- true }()
			for i := 0; i < requestCt; i++ {
				if err = router.HandleConn(c); err != nil {
					ch <- testResult{err, nil}
					return
				}
			}
		}(c)
	}

	for i := 0; i < clientCt; i++ {
		<-done
	}

	ch <- testResult{nil, nil}
}

// Proxy dials a router, creates a circuit, and sends a message over
// the circuit.
func runProxySendMessage(proxy *ProxyContext, rAddr, dAddr string, msg []byte) ([]byte, error) {
	c, err := proxy.CreateCircuit(rAddr, dAddr)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	if err = c.SendMessage(msg); err != nil {
		return nil, err
	}

	// dummyServer receives one message and replies. Without this line,
	// the router will report a broken pipe.
	return c.ReceiveMessage()
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
	routerAddr := router.proxyListener.Addr().String()

	// Wait for a connection from the proxy.
	ch := make(chan bool)
	go func(ch chan<- bool) {
		c, _ := router.AcceptProxy()
		defer c.Close()
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

// Test CREATE and DESTROY.
func TestCreateDestroy(t *testing.T) {
	router, proxy, domain, err := makeContext(1)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	defer proxy.Close()
	defer os.RemoveAll(path.Base(domain.ConfigPath))
	rAddr := router.proxyListener.Addr().String()

	// The address doesn't matter here because no packets will be sent on
	// the established circuit.
	fakeAddr := "127.0.0.1:0"
	ch := make(chan testResult)
	go runRouterHandleOneProxy(router, 3, ch)

	c, err := proxy.CreateCircuit(rAddr, fakeAddr)
	if err != nil {
		t.Error(err)
	}

	if err = c.SendMessage([]byte("hola!")); err != nil {
		t.Error(err)
	}

	if err = proxy.DestroyCircuit(c); err != nil {
		t.Error(err)
	}

	res := <-ch
	if res.err != io.EOF {
		t.Error("should have gotten EOF from router, but got:", res.err)
	}

	sendCt := len(router.sendQueue.nextConn)
	replyCt := len(router.replyQueue.nextConn)
	if sendCt > 0 || replyCt > 0 {
		t.Errorf("%d send, %d reply connections open, should be 0", sendCt, replyCt)
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

	msg := make([]byte, CellBytes+1)
	for i := 0; i < len(msg); i++ {
		msg[i] = byte(i)
	}

	// This cell is just right.
	go runRouterReadCell(router, ch)
	if err = runProxyWriteCell(proxy, router.proxyListener.Addr().String(), msg[:CellBytes]); err != nil {
		t.Error(err)
	}
	res := <-ch
	if res.err != nil && res.err != io.EOF {
		t.Error(res.err)
	} else if bytes.Compare(res.msg, msg[:CellBytes]) != 0 {
		t.Errorf("Server got: %s", res.msg)
	}

	// This cell is too big.
	go runRouterReadCell(router, ch)
	if err = runProxyWriteCell(proxy, router.proxyListener.Addr().String(), msg); err != errCellLength {
		t.Error("runProxyWriteCell(): should have returned errCellLength")
	}
	res = <-ch
	if res.err != io.EOF {
		t.Error("runRouterReadCell(): should have returned EOF.")
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
		37,        // A short message
		CellBytes, // A cell
		len(msg),  // A long message
	}

	go runDummyServer(len(trials), 1, dstCh, dstAddrCh)
	dstAddr := <-dstAddrCh
	rAddr := router.proxyListener.Addr().String()

	for _, l := range trials {

		go runRouterHandleOneProxy(router, 2, routerCh)
		reply, err := runProxySendMessage(proxy, rAddr, dstAddr, msg[:l])
		if err != nil {
			t.Errorf("relay (length=%d): %s", l, err)
		}

		res = <-routerCh
		if res.err != nil {
			t.Errorf("relay (length=%d): %s", l, res.err)
		}

		res = <-dstCh
		if res.err != nil {
			t.Error(res.err)
		} else if bytes.Compare(reply, msg[:l]) != 0 {
			t.Errorf("relay (length=%d): received: %v", l, reply)
			t.Errorf("relay (length=%d): sent: %x", l, msg[:l])
		}
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
	routerAddr := router.proxyListener.Addr().String()
	cell := make([]byte, CellBytes)
	ch := make(chan testResult)

	go runRouterHandleOneProxy(router, 2, ch)
	c, err := proxy.DialRouter(network, routerAddr)
	if err != nil {
		t.Error(err)
	}

	// Unrecognized cell type.
	cell[0] = 0xff
	if _, err = c.Write(cell); err != nil {
		t.Error(err)
	}
	_, err = c.ReceiveMessage()
	if err == nil {
		t.Error("ReceiveMessage incorrectly succeeded")
	}

	// Message too long.
	cell[0] = msgCell
	binary.PutUvarint(cell[1:], uint64(MaxMsgBytes+1))
	if _, err := c.Write(cell); err != nil {
		t.Error(err)
	}
	_, err = c.ReceiveMessage()
	if err == nil {
		t.Error("ReceiveMessage incorrectly succeeded")
	}
	<-ch
	c.Close()

	// Bogus destination.
	go runRouterHandleOneProxy(router, 2, ch)
	c, err = proxy.CreateCircuit(routerAddr, "127.0.0.1:9999")
	if err != nil {
		t.Error(err)
	}
	if err = c.SendMessage([]byte("Are you there?")); err != nil {
		t.Error(err)
	}
	_, err = c.ReceiveMessage()
	if err == nil {
		t.Error("Receive message incorrectly succeeded")
	}
	<-ch
	c.Close()

	// Multihop circuits not supported yet.
	// go runRouterHandleOneProxy(router, 1, ch)
	// c, err = proxy.CreateCircuit(routerAddr, "one:234", "two:34", "three:4")
	// if err == nil {
	// 	t.Error("should have gotten \"multi-hop circuits not implemented\" from router")
	// }
	// <-ch
	// c.Close()
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
	routerAddr := router.proxyListener.Addr().String()
	ch := make(chan testResult)

	// The proxy should get a timeout if it's the only connecting client.
	go runRouterHandleProxy(router, 1, 1, ch)
	hostAddr := genHostname() + ":80"
	_, err = proxy.CreateCircuit(routerAddr, hostAddr)
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
	defer router.Close()
	defer proxy.Close()
	defer os.RemoveAll(path.Base(domain.ConfigPath))
	routerAddr := router.proxyListener.Addr().String()
	ch := make(chan testResult)
	done := make(chan bool)

	go runRouterHandleProxy(router, 2, 2, ch)

	// Proxy 1 creates a circuit, sends a message and awaits a reply.
	go func() {
		c, err := proxy.CreateCircuit(routerAddr, genHostname()+":80")
		if err != nil {
			t.Error(err)
		}
		if err = c.SendMessage([]byte("hello")); err != nil {
			t.Error(err)
		}
		if _, err = c.ReceiveMessage(); err == nil {
			t.Error("receiveMessage incorrectly succeeded")
		}
		done <- true
	}()

	// Proxy 2 just creates a circuit.
	go func() {
		_, err = proxy.CreateCircuit(routerAddr, genHostname()+":80")
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
func TestMixnet(t *testing.T) {

	clientCt := 10
	router, proxy, domain, err := makeContext(clientCt)
	if err != nil {
		t.Fatal(err)
	}
	proxy.Close()
	defer router.Close()
	defer os.RemoveAll(path.Base(domain.ConfigPath))
	routerAddr := router.proxyListener.Addr().String()

	var res testResult
	clientCh := make(chan testResult)
	proxyCh := make(chan testResult)
	routerCh := make(chan testResult)
	dstCh := make(chan testResult)
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
			go runSocksServerOne(proxy, routerAddr, proxyCh)

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
	for i := 0; i < clientCt; i++ {
		res = <-routerCh
		if res.err != nil && res.err != io.EOF {
			t.Error(res.err)
		}
	}
}
