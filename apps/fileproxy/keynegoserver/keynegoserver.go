// Copyright (c) 2014, Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"os"

	"github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/net"
)

var network = flag.String("network", "tcp", "The network to use for connections")
var addr = flag.String("addr", "localhost:8124", "The address to listen on")
var domainPass = flag.String("password", "BogusPass", "The domain password for the policy key")
var configPath = flag.String("config", "tao.config", "The Tao domain config")

func main() {
	flag.Parse()
	domain, err := tao.LoadDomain(*configPath, []byte(*domainPass))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't load the config path %s: %s\n", *configPath, err)
		return
	}

	// Set up temporary keys for the connection, since the only thing that
	// matters to the remote client is that they receive a correctly-signed new
	// attestation from the policy key.
	// JLM:  I left this in place but I'm not sure what a TLS connection with a 
	//   self signed Cert buys in terms of security.  The security of this protocol should
	//   not depend on the confidentiality or intergity of the channel.  All that said,
	//   if we do ever distribute a signed keynegoserver cert for this TLS channel, it would
	//   be good.
	keys, err := tao.NewTemporaryKeys(tao.Signing)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't set up temporary keys for the connection:", err)
		return
	}
	keys.Cert, err = keys.SigningKey.CreateSelfSignedX509(&pkix.Name{
		Organization: []string{"Google Tao Demo"}})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't set up a self-signed cert:", err)
	return
	}

	tlsc, err := net.EncodeTLSCert(keys)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't encode a TLS cert:", err)
		return
	}
	conf := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
	}
	sock, err := tls.Listen(*network, *addr, conf)

	fmt.Println("keynegoserver: accepting connections")
	for {
		conn, err := sock.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Couldn't accept a connection on %s: %s\n", *addr, err)
			return
		}

		go net.HandleCARequest(conn, domain.Keys.SigningKey, domain.Guard)
	}
}
