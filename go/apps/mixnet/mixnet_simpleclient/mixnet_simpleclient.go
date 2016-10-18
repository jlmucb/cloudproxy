// Copyright (c) 2016, Google Inc. All rights reserved.
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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"

	"github.com/golang/glog"

	"golang.org/x/net/proxy"
)

var proxyAddr = flag.String("proxy_addr", "127.0.0.1:8000", "Address and port of the proxy.")
var destination = flag.String("dest_addr", "127.0.0.1:9000", "Destination address.")
var network = flag.String("network", "tcp", "Network protocol for the Tao-delegated mixnet router.")
var id = flag.Int("id", 0, "ID of the client.")

// Simple client that uses socks5 to write to a TLS server
func main() {
	flag.Parse()

	dialer, err := proxy.SOCKS5(*network, *proxyAddr, nil, proxy.Direct)
	if err != nil {
		glog.Fatal(err)
	}

	c, err := dialer.Dial(*network, *destination)
	if err != nil {
		glog.Fatal(err)
	}
	defer c.Close()

	config := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		InsecureSkipVerify: true,
	}

	tlsConn := tls.Client(c, config)

	msg := []byte(fmt.Sprintf("My name is %d.", *id))

	if _, err = tlsConn.Write(msg); err != nil {
		glog.Fatal(err)
	}

	res := make([]byte, len(msg))
	bytes, err := tlsConn.Read(res)
	if err != nil {
		glog.Fatal(err)
	}

	if string(msg) != string(res[:bytes]) {
		glog.Fatal(errors.New("Expected:" + string(msg) + ". Got: " + string(res[:bytes]) + "."))
	} else {
		glog.Info("Got: ", string(res[:bytes]))
	}

	glog.Flush()
}
