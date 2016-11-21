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
	"bufio"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jlmucb/cloudproxy/go/apps/mixnet"
)

// serveClient runs the SOCKS5 proxy for clients and connects them
// to the mixnet.
func serveClients(routerAddrs []string, exitKey *[32]byte, proxy *mixnet.ProxyContext) error {
	for {
		c, err := proxy.Accept()
		if err != nil {
			return err
		}

		go func(c net.Conn) {
			defer c.Close()
			// Length of the slice determines path length,
			// so insert some empty strings
			err := proxy.ServeClient(c, append(routerAddrs, c.(*mixnet.SocksConn).DestinationAddr()), exitKey)
			if err != nil {
				log.Fatal(err)
			}
		}(c)
	}
}

// Command line arguments.
var (
	network         = flag.String("network", "tcp", "Network protocol for the mixnet proxy and router.")
	configPath      = flag.String("config", "tao.config", "Path to domain configuration file.")
	timeoutDuration = flag.String("timeout", "10s", "Timeout on TCP connections, e.g. \"10s\".")
	proxyAddr       = flag.String("addr", ":1080", "Address and port to listen to client's connections.")
	routerAddr      = flag.String("router_addr", "127.0.0.1:8123", "Address and port for the Tao-delegated mixnet router.")
	directories     = flag.String("dirs", "directories", "File containing addresses of directories.")

	//only used if you don't want to download the keys from the directories
	keyFile = flag.String("exit_key", "", "PEM encoded exit key")
	//only used for testing, where users pick the circuit
	circuit = flag.String("circuit", "", "A file with pre-built circuit.")
)

func main() {
	flag.Parse()
	timeout, err := time.ParseDuration(*timeoutDuration)
	if err != nil {
		log.Fatalln("proxy: failed to parse timeout duration:", err)
	}

	f, err := os.Open(*directories)
	if err != nil {
		log.Fatal(err)
	}
	scan := bufio.NewScanner(f)
	dirs := []string{}
	for scan.Scan() {
		dirs = append(dirs, scan.Text())
	}

	proxy, err := mixnet.NewProxyContext(*configPath, *network, *proxyAddr, dirs, timeout)
	if err != nil {
		log.Fatalln("failed to configure proxy:", err)
	}
	defer proxy.Close()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	go func() {
		sig := <-sigs
		proxy.Close()
		log.Println("proxy: closing on signal:", sig)
		signo := int(sig.(syscall.Signal))
		os.Exit(0x80 + signo)
	}()

	var exitKey *[32]byte = nil
	if *keyFile != "" {
		var key [32]byte
		kb, err := ioutil.ReadFile(*keyFile)
		if err != nil {
			log.Fatalln("No exit key file..")
		}
		block, _ := pem.Decode(kb)
		copy(key[:], block.Bytes)
		exitKey = &key
	}

	if *circuit == "" {
		if err = serveClients([]string{*routerAddr}, exitKey, proxy); err != nil {
			log.Fatalln("proxy: error while serving:", err)
		}
	} else {
		f, err := os.Open(*circuit)
		if err != nil {
			log.Fatal(err)
		}
		scan := bufio.NewScanner(f)
		routers := []string{}
		for scan.Scan() {
			routers = append(routers, scan.Text())
		}
		if err = serveClients(routers, exitKey, proxy); err != nil {
			log.Fatalln("proxy: error while serving:", err)
		}
	}
}
