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
	"flag"
	"io"
	"net"

	"github.com/golang/glog"
	"github.com/jlmucb/cloudproxy/go/apps/mixnet"
)

var addr = flag.String("addr", ":8123", "Port to listen to.")
var network = flag.String("network", "tcp", "Network protocol for the Tao-delegated mixnet router.")
var cert_file = flag.String("cert", "cert.pem", "Name of the certificate file")
var key_file = flag.String("key", "key.pem", "Name of the key file")

// A simple TLS server echoes back client's message.
func main() {
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*cert_file, *key_file)
	if err != nil {
		glog.Fatal(err)
	}
	config := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequestClientCert,
	}
	l, err := tls.Listen(*network, *addr, config)
	if err != nil {
		glog.Fatal(err)
	}
	defer l.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			glog.Fatal(err)
		}

		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, mixnet.MaxMsgBytes+1)
			for {
				bytes, err := c.Read(buf)
				if err != nil {
					if err == io.EOF {
						return
					}
					glog.Fatal(err)
				} else {
					_, err := c.Write(buf[:bytes])
					if err != nil {
						glog.Fatal(err)
					}
				}
			}
		}(c)
	}

	glog.Flush()
}
