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

package mixnet

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"os"
	"path"
	"testing"

	netproxy "golang.org/x/net/proxy"
)

// Run proxy server.
func runSocksServerOne(proxy *ProxyContext, rAddrs []string, ch chan<- testResult) {
	c, err := proxy.Accept()
	if err != nil {
		ch <- testResult{err, nil}
		return
	}
	defer c.Close()
	addr := c.(*SocksConn).dstAddr

	circuit := make([]string, len(rAddrs)+1)
	copy(circuit, rAddrs)
	circuit[len(rAddrs)] = addr
	id, err := proxy.CreateCircuit(circuit)
	if err != nil {
		ch <- testResult{err, nil}
		return
	}

	proxy.clients[id] = c

	if err = proxy.HandleClient(id); err != nil {
		ch <- testResult{err, nil}
		return
	}

	if err = proxy.DestroyCircuit(id); err != nil {
		ch <- testResult{err, nil}
		return
	}

	ch <- testResult{err, []byte(addr)}
}

// Run a proxy server that accepts more than one message
func runSocksServer(proxy *ProxyContext, rAddrs []string, ch chan<- testResult) {
	c, err := proxy.Accept()
	if err != nil {
		ch <- testResult{err, nil}
		return
	}
	defer c.Close()
	addr := c.(*SocksConn).dstAddr

	circuit := make([]string, len(rAddrs)+1)
	copy(circuit, rAddrs)
	circuit[len(rAddrs)] = addr

	ch <- testResult{proxy.ServeClient(c, circuit), []byte(addr)}
}

// Connect to a destination through a mixnet proxy, send a message,
// and wait for a response.
func runSocksClient(pAddr, dAddr string, msg []byte) testResult {
	dialer, err := netproxy.SOCKS5(network, pAddr, nil, netproxy.Direct)
	if err != nil {
		return testResult{err, nil}
	}

	c, err := dialer.Dial(network, dAddr)
	if err != nil {
		return testResult{err, nil}
	}
	defer c.Close()

	if _, err = c.Write(msg); err != nil {
		return testResult{err, nil}
	}

	bytes, err := c.Read(msg)
	if err != nil {
		return testResult{err, nil}
	}

	return testResult{nil, msg[:bytes]}
}

// Connect to a destination through a mixnet proxy, send a message,
// and wait for a response.
func runTLSClient(pAddr, dAddr string, msg []byte) testResult {
	dialer, err := netproxy.SOCKS5(network, pAddr, nil, netproxy.Direct)
	if err != nil {
		return testResult{err, nil}
	}

	c, err := dialer.Dial(network, dAddr)
	if err != nil {
		return testResult{err, nil}
	}
	defer c.Close()

	config := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		InsecureSkipVerify: true,
	}

	tlsConn := tls.Client(c, config)

	if _, err = tlsConn.Write(msg); err != nil {
		return testResult{err, nil}
	}

	bytes, err := tlsConn.Read(msg)
	if err != nil {
		return testResult{err, nil}
	}

	return testResult{nil, msg[:bytes]}
}

// Test the SOCKS proxy server.
func TestSocks(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "test_socks")
	if err != nil {
		t.Fatal(err)
	}
	d, err := makeTrivialDomain(tempDir)
	if err != nil {
		t.Fatal(err)
	}

	proxy, err := makeProxyContext(localAddr, d)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	defer os.RemoveAll(path.Base(d.ConfigPath))
	proxyAddr := proxy.listener.Addr().String()

	ch := make(chan testResult)
	go func() {
		c, err := proxy.Accept()
		if err != nil {
			ch <- testResult{err, nil}
			return
		}
		defer c.Close()
		ch <- testResult{nil, []byte(c.(*SocksConn).dstAddr)}
	}()

	dialer, err := netproxy.SOCKS5(network, proxyAddr, nil, netproxy.Direct)
	if err != nil {
		t.Error(err)
	}

	// The value of dstAddr doesn't matter here because the client never
	// tries to send anything to it.
	c, err := dialer.Dial(network, "127.0.0.1:1234")
	if err != nil {
		t.Error(err)
	}
	defer c.Close()

	res := <-ch
	if res.err != nil {
		t.Error(res.err)
	} else {
		t.Log("server got:", string(res.msg))
	}
}
