// Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"net"
	"strings"

	"github.com/golang/glog"
	"github.com/jlmucb/cloudproxy/go/tao"
	taonet "github.com/jlmucb/cloudproxy/go/tao/net"
)

var serverHost = flag.String("host", "0.0.0.0", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var serverAddr string // see main()
var pingCount = flag.Int("n", 5, "Number of client/server pings")
var demoAuth = flag.String("auth", "tao", "\"tcp\", \"tls\", or \"tao\"")
var configPath = flag.String("config", "tao.config", "The Tao domain config")
var ca = flag.String("ca", "", "address for Tao CA, if any")

var subprinRule = "(forall P: forall Hash: TrustedProgramHash(Hash) and Subprin(P, %v, Hash) implies Authorized(P, \"Execute\"))"

func newTempCAGuard(v *tao.Verifier) (tao.Guard, error) {
	g := tao.NewTemporaryDatalogGuard()
	vprin := v.ToPrincipal()
	rule := fmt.Sprintf(subprinRule, vprin)

	if err := g.AddRule(rule); err != nil {
		return nil, err
	}
	return g, nil
}

func doResponse(conn net.Conn, responseOk chan<- bool) {
	defer conn.Close()

	// Both the TLS and the Tao/TLS connections and listeners handle
	// authorization during the Accept operation. So, no extra authorization is
	// needed here.
	msg, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		glog.Fatalf("server: can't read: %s\n", err.Error())
		responseOk <- false
		return
	}
	msg = strings.TrimSpace(msg)
	glog.Infof("server: got message: %s\n", msg)
	responseOk <- true
	fmt.Fprintf(conn, "echo(%s)\n", msg)
	glog.Flush()
}

func doServer() {
	var sock net.Listener
	var err error
	var keys *tao.Keys
	network := "tcp"
	domain, err := tao.LoadDomain(*configPath, nil)
	if err != nil {
		return
	}

	switch *demoAuth {
	case "tcp":
		sock, err = net.Listen(network, serverAddr)
		if err != nil {
			glog.Info("server: couldn't listen to the network: %s\n", err)
			return
		}

	case "tls", "tao":
		// Generate a private/public key for this hosted program (hp) and
		// request attestation from the host of the statement "hp speaksFor
		// host". The resulting certificate, keys.Delegation, is a chain of
		// "says" statements extending to the policy key. The policy is
		// checked by the host before this program is executed.
		keys, err = tao.NewTemporaryTaoDelegatedKeys(tao.Signing, tao.Parent())
		if err != nil {
			glog.Info("server: failed to generate delegated keys: %s\n", err)
			return
		}

		// Create a certificate for the hp.
		keys.Cert, err = keys.SigningKey.CreateSelfSignedX509(&pkix.Name{
			Organization: []string{"Google Tao Demo"}})
		if err != nil {
			glog.Info("server: couldn't create certificate: %s\n", err)
			return
		}

		g := domain.Guard
		if *ca != "" {
			// Replace keys.Delegation with a "says" statement directly from
			// the policy key.
			na, err := taonet.RequestTruncatedAttestation(network, *ca, keys, domain.Keys.VerifyingKey)
			if err != nil {
				glog.Infof("server: truncated attestation request failed: %s\n", err)
				return
			}
			keys.Delegation = na

			g, err = newTempCAGuard(domain.Keys.VerifyingKey)
			if err != nil {
				glog.Infof("server: couldn't set up a new guard: %s\n", err)
				return
			}
		}

		tlsc, err := taonet.EncodeTLSCert(keys)
		if err != nil {
			glog.Infof("server: couldn't encode TLS certificate: %s\n", err)
			return
		}

		conf := &tls.Config{
			RootCAs:            x509.NewCertPool(),
			Certificates:       []tls.Certificate{*tlsc},
			InsecureSkipVerify: true,
			ClientAuth:         tls.RequireAnyClientCert,
		}

		if *demoAuth == "tao" {
			sock, err = taonet.Listen(network, serverAddr, conf, g, domain.Keys.VerifyingKey, keys.Delegation)
			if err != nil {
				glog.Infof("sever: couldn't create a taonet listener: %s\n", err)
				return
			}
		} else {
			sock, err = tls.Listen(network, serverAddr, conf)
			if err != nil {
				glog.Infof("server: couldn't create a tls listener: %s\n", err)
				return
			}
		}
	}

	glog.Infof("server: listening at %s using %s authentication.\n", serverAddr, *demoAuth)
	defer sock.Close()

	pings := make(chan bool, 5)
	connCount := 0

	go func() {
		for connCount = 0; connCount < *pingCount || *pingCount < 0; connCount++ { // negative means forever
			conn, err := sock.Accept()
			if err != nil {
				glog.Infof("server: can't accept connection: %s\n", err.Error())
				return
			}
			go doResponse(conn, pings)
		}
	}()

	pingGood := 0
	pingFail := 0

	for {
		select {
		case ok := <-pings:
			if ok {
				pingGood++
			} else {
				pingFail++
			}
		}
	}
}

func main() {
	flag.Parse()
	serverAddr = net.JoinHostPort(*serverHost, *serverPort)
	switch *demoAuth {
	case "tcp", "tls", "tao":
	default:
		glog.Fatalf("unrecognized authentication mode: %s\n", *demoAuth)
		return
	}

	glog.Info("Go Tao Demo Server")

	if tao.Parent() == nil {
		glog.Fatal("can't continue: No host Tao available")
		return
	}

	doServer()
	glog.Info("Server Done")
	glog.Flush()
}
