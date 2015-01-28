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
	"log"
	"net"
	"os"
	"strings"

	"github.com/jlmucb/cloudproxy/tao"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
)

var serverHost = flag.String("host", "0.0.0.0", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var serverAddr string // see main()
var pingCount = flag.Int("n", 5, "Number of client/server pings")
var demoAuth = flag.String("auth", "tao", "\"tcp\", \"tls\", or \"tao\"")
var configPath = flag.String("config", "tao.config", "The Tao domain config")
var ca = flag.String("ca", "", "address for Tao CA, if any")

var subprinRule = "(forall P: forall Hash: TrustedProgramHash(Hash) and Subprin(P, %v, Hash) implies MemberProgram(P))"
var argsRule = "(forall Y: forall P: forall S: MemberProgram(P) and TrustedArgs(S) and Subprin(Y, P, S) implies Authorized(Y, \"Execute\"))"
var demoRule = "TrustedArgs(ext.Args(%s))"

func newTempCAGuard(v *tao.Verifier) (tao.Guard, error) {
	g := tao.NewTemporaryDatalogGuard()
	vprin := v.ToPrincipal()
	rule := fmt.Sprintf(subprinRule, vprin)

	// Add a rule that says that valid args are the ones we were called with.
	args := ""
	for i, a := range os.Args {
		if i > 0 {
			args += ", "
		}
		args += "\"" + a + "\""
	}
	authRule := fmt.Sprintf(demoRule, args)

	if err := g.AddRule(rule); err != nil {
		return nil, err
	}
	if err := g.AddRule(argsRule); err != nil {
		return nil, err
	}
	if err := g.AddRule(authRule); err != nil {
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
		fmt.Printf("server: can't read: %s\n", err.Error())
		conn.Close()
		responseOk <- false
		return
	}
	msg = strings.TrimSpace(msg)
	fmt.Printf("server: got message: %s\n", msg)
	responseOk <- true
	fmt.Fprintf(conn, "echo(%s)\n", msg)
	conn.Close()
}

func doServer(done chan<- bool) {
	var sock net.Listener
	var err error
	var keys *tao.Keys
	network := "tcp"
	domain, err := tao.LoadDomain(*configPath, nil)
	if err != nil {
		done <- true
		return
	}

	switch *demoAuth {
	case "tcp":
		sock, err = net.Listen(network, serverAddr)
		if err != nil {
			log.Fatalf("Couldn't listen to the network: %s\n", err)
		}
	case "tls", "tao":
		keys, err = tao.NewTemporaryTaoDelegatedKeys(tao.Signing, tao.Parent())
		if err != nil {
			done <- true
			return
		}
		keys.Cert, err = keys.SigningKey.CreateSelfSignedX509(&pkix.Name{
			Organization: []string{"Google Tao Demo"}})
		if err != nil {
			done <- true
			return
		}

		g := domain.Guard
		if *ca != "" {
			na, err := taonet.RequestTruncatedAttestation(network, *ca, keys, domain.Keys.VerifyingKey)
			if err != nil {
				done <- true
				return
			}

			keys.Delegation = na
			g, err = newTempCAGuard(domain.Keys.VerifyingKey)
			if err != nil {
				fmt.Printf("server: couldn't set up a new guard: %s\n", err)
				return
			}
		}

		tlsc, err := taonet.EncodeTLSCert(keys)
		if err != nil {
			done <- true
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
				log.Fatalf("Couldn't create a taonet listener: %s\n", err)
			}
		} else {
			sock, err = tls.Listen(network, serverAddr, conf)
			if err != nil {
				log.Fatalf("Couldn't create a tls listener: %s\n", err)
			}
		}
	}
	fmt.Printf("server: listening at %s using %s authentication.\n", serverAddr, *demoAuth)

	pings := make(chan bool, 5)
	connCount := 0

	go func() {
		for connCount = 0; connCount < *pingCount || *pingCount < 0; connCount++ { // negative means forever
			conn, err := sock.Accept()
			if err != nil {
				fmt.Printf("server: can't accept connection: %s\n", err.Error())
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

	sock.Close()
	fmt.Printf("server: handled %d connections, finished %d ok, %d bad pings\n",
		connCount, pingGood, pingFail)

	done <- true
}

func main() {
	flag.Parse()
	serverAddr = net.JoinHostPort(*serverHost, *serverPort)
	switch *demoAuth {
	case "tcp", "tls", "tao":
	default:
		fmt.Printf("unrecognized authentication mode: %s\n", *demoAuth)
		return
	}

	fmt.Printf("Go Tao Demo Server\n")

	if tao.Parent() == nil {
		fmt.Printf("can't continue: No host Tao available\n")
		return
	}

	serverDone := make(chan bool, 1)

	go doServer(serverDone)
	<-serverDone
	fmt.Printf("Server Done\n")
}
