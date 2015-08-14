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
	"testing"

	netproxy "golang.org/x/net/proxy"
)

// Run proxy server.
func runSocksServerOne(proxy *ProxyContext, ch chan<- testResult) {
	c, err := proxy.Accept()
	if err != nil {
		ch <- testResult{err, nil}
		return
	}
	defer c.Close()
	addr := c.(*SocksConn).dstAddr

	d, err := proxy.CreateCircuit(routerAddr, addr)
	if err != nil {
		ch <- testResult{err, nil}
		return
	}

	if err = proxy.HandleClient(c, d); err != nil {
		ch <- testResult{err, nil}
		return
	}

	if err = proxy.DestroyCircuit(d); err != nil {
		ch <- testResult{err, nil}
		return
	}

	ch <- testResult{err, []byte(addr)}
}

// Connect to a destination through a mixnet proxy, send a message,
// and wait for a response.
func runSocksClient(proxyAddr string, msg []byte) testResult {
	dialer, err := netproxy.SOCKS5(network, proxyAddr, nil, netproxy.Direct)
	if err != nil {
		return testResult{err, nil}
	}

	c, err := dialer.Dial(network, dstAddr)
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

// Test the SOCKS proxy server.
func TestSocks(t *testing.T) {

	proxy, err := makeProxyContext(proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	proxyAddr = proxy.listener.Addr().String()

	ch := make(chan testResult)
	go func() {
		c, err := proxy.Accept()
		if err != nil {
			ch <- testResult{err, nil}
			return
		}
		c.Close()
		ch <- testResult{nil, []byte(c.(*SocksConn).dstAddr)}
	}()

	dialer, err := netproxy.SOCKS5(network, proxyAddr, nil, netproxy.Direct)
	if err != nil {
		t.Error(err)
	}

	c, err := dialer.Dial(network, dstAddr)
	if err != nil {
		t.Error(err)
	}
	c.Close()

	res := <-ch
	if res.err != nil {
		t.Error(res.err)
	} else {
		t.Log("server got:", string(res.msg))
	}
}
