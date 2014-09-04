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
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
)

var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var serverAddr string // see main()
var localMode = flag.Bool("local", true, "Run host demo")
var clientMode = flag.Bool("client", true, "Run demo client")
var serverMode = flag.Bool("server", true, "Run demo server")
var pingCount = flag.Int("n", 5, "Number of client/server pings")
var demoAuth = flag.String("auth", "tao", "\"tcp\", \"tls\", or \"tao\"")

// client/server driver

func doRequest() bool {
	fmt.Printf("client: connecting to %s using %s authentication.\n", serverAddr, *demoAuth)
	var conn net.Conn
	var err error
	network := "tcp"

	switch *demoAuth {
	case "tcp":
		conn, err = net.Dial(network, serverAddr)
	case "tls":
		conn, _, err = taonet.DialTLS(network, serverAddr)
	case "tao":
		conn, err = taonet.Dial(network, serverAddr, tao.LiberalGuard)
	}
	if err != nil {
		fmt.Printf("client: error connecting to %s: %s\n", serverAddr, err.Error())
		return false
	}
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "Hello\n")
	if err != nil {
		fmt.Printf("client: can't write: %s\n", err.Error())
		return false
	}
	msg, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Printf("client can't read: %s\n", err.Error())
		return false
	}
	msg = strings.TrimSpace(msg)
	fmt.Printf("client: got reply: %s\n", msg)
	return true
}

func doClient() {
	pingGood := 0
	pingFail := 0
	for i := 0; i < *pingCount || *pingCount < 0; i++ { // negative means forever
		if doRequest() {
			pingGood++
		} else {
			pingFail++
		}
		fmt.Printf("client: made %d connections, finished %d ok, %d bad pings\n",
			i+1, pingGood, pingFail)
	}
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

func doServer(stop chan bool, ready, done chan<- bool) {
	var sock net.Listener
	var err error
	var keys *tao.Keys
	network := "tcp"

	switch *demoAuth {
	case "tcp":
		sock, err = net.Listen(network, serverAddr)
	case "tls", "tao":
		keys, err = tao.NewTemporaryTaoDelegatedKeys(tao.Signing, tao.Parent())
		if err != nil {
			ready <- false
			done <- true
			return
		}
		keys.Cert, err = keys.SigningKey.CreateSelfSignedX509(&pkix.Name{
			Organization: []string{"Google Tao Demo"}})
		if err != nil {
			ready <- false
			done <- true
			return
		}

		tlsc, err := taonet.EncodeTLSCert(keys)
		if err != nil {
			ready <- false
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
			sock, err = taonet.Listen(network, serverAddr, conf, tao.LiberalGuard, keys.Delegation)
		} else {
			sock, err = tls.Listen(network, serverAddr, conf)
		}
	}
	if err != nil {
		fmt.Printf("server: can't listen at %s: %s\n", serverAddr, err.Error())
		ready <- false
		done <- true
		return
	}
	fmt.Printf("server: listening at %s using %s authentication.\n", serverAddr, *demoAuth)
	ready <- true

	pings := make(chan bool, 10)
	connCount := 0

	go func() {
		for connCount = 0; connCount < *pingCount || *pingCount < 0; connCount++ { // negative means forever
			conn, err := sock.Accept()
			if err != nil {
				fmt.Printf("server: can't accept connection: %s\n", err.Error())
				stop <- true
				return
			}
			go doResponse(conn, pings)
		}
	}()

	pingGood := 0
	pingFail := 0

loop:
	for {
		select {
		case <-stop:
			break loop
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

// Tao Host demo

func hostTaoDemo() error {
	name, err := tao.Parent().GetTaoName()
	if err != nil {
		return err
	}
	fmt.Printf("My root name is %s\n", name)

	// TODO(kwalsh) Make a convenience function for this
	var args []auth.Term
	for _, arg := range os.Args {
		args = append(args, auth.Str(arg))
	}
	e := auth.PrinExt{Name: "Args", Arg: args}
	err = tao.Parent().ExtendTaoName(auth.SubPrin{e})
	if err != nil {
		return err
	}

	name, err = tao.Parent().GetTaoName()
	if err != nil {
		return err
	}
	fmt.Printf("My full name is %s\n", name)

	random, err := tao.Parent().GetRandomBytes(10)
	if err != nil {
		return err
	}
	fmt.Printf("Random bytes  : % x\n", random)

	n, err := tao.Parent().Rand().Read(random)
	if err != nil {
		return err
	}
	fmt.Printf("%d more bytes : % x\n", n, random)

	secret, err := tao.Parent().GetSharedSecret(10, tao.SharedSecretPolicyDefault)
	if err != nil {
		return err
	}
	fmt.Printf("Shared secret : % x\n", secret)

	sealed, err := tao.Parent().Seal(random, tao.SealPolicyDefault)
	if err != nil {
		return err
	}
	fmt.Printf("Sealed bytes  : % x\n", sealed)

	unsealed, policy, err := tao.Parent().Unseal(sealed)
	if err != nil {
		return err
	}
	if policy != tao.SealPolicyDefault {
		return errors.New("unexpected policy on unseal")
	}
	fmt.Printf("Unsealed bytes: % x\n", unsealed)

	return nil
}

func main() {
	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort
	switch *demoAuth {
	case "tcp", "tls", "tao":
	default:
		fmt.Printf("unrecognized authentication mode: %s\n", *demoAuth)
		return
	}

	fmt.Printf("Go Tao Demo\n")

	if !tao.Hosted() {
		fmt.Printf("can't continue: No host Tao available\n")
		return
	}

	if *localMode {
		err := hostTaoDemo()
		if err != nil {
			fmt.Printf("error: %s\n", err.Error())
			return
		}
	}

	serverStop := make(chan bool, 1)
	serverReady := make(chan bool, 1)
	serverDone := make(chan bool, 1)

	// TODO(tmroeder): use the Domain and the tao parent to set up the keys and
	// the guard. Also need to hook the datalog guard into the domain and get
	// the basic tests working with this guard, especially execution
	// authorization.
	if *serverMode {
		go doServer(serverStop, serverReady, serverDone)
	} else {
		serverReady <- true
		serverDone <- true
	}

	if *clientMode {
		ok := <-serverReady
		if ok {
			doClient()
		}
		serverStop <- true
	}

	<-serverDone
	fmt.Printf("Done\n")
}
