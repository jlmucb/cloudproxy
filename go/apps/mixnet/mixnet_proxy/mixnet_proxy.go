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

package main

import (
	"flag"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/jlmucb/cloudproxy/go/apps/mixnet"
)

// serveClient runs the SOCKS5 proxy for clients and connects them
// to the mixnet.
func serveClients(routerAddr string, proxy *mixnet.ProxyContext) error {
	for {
		c, err := proxy.Accept()
		if err != nil {
			return err
		}

		go func(c net.Conn) {
			defer c.Close()
			proxy.ServeClient(c, routerAddr, c.(*mixnet.SocksConn).DestinationAddr())
		}(c)
	}
}

// Command line arguments.
var proxyAddr = flag.String("proxy_addr", "127.0.0.1:1080", "Address and port for the Tao-delegated mixnet router.")
var routerAddr = flag.String("router_addr", "127.0.0.1:8123", "Address and port for the Tao-delegated mixnet router.")
var network = flag.String("network", "tcp", "Network protocol for the mixnet proxy and router.")
var configPath = flag.String("config", "tao.config", "Path to domain configuration file.")
var timeoutDuration = flag.String("timeout", "10s", "Timeout on TCP connections, e.g. \"10s\".")

func main() {
	flag.Parse()
	timeout, err := time.ParseDuration(*timeoutDuration)
	if err != nil {
		glog.Fatalf("proxy: failed to parse timeout duration: %s", err)
	}

	proxy, err := mixnet.NewProxyContext(*configPath, *network, *proxyAddr, timeout)
	if err != nil {
		glog.Fatalf("failed to configure proxy: %s", err)
	}
	defer proxy.Close()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	go func() {
		sig := <-sigs
		proxy.Close()
		glog.Infof("router: closing on signal: %s", sig)
		signo := int(sig.(syscall.Signal))
		os.Exit(0x80 + signo)
	}()

	if err = serveClients(*routerAddr, proxy); err != nil {
		glog.Errorf("proxy: error while serving: %s", err)
	}

	glog.Flush()
}
