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
var localMode = flag.Bool("local", true, "Run fileclient")
var clientMode = flag.Bool("client", true, "Run fileclient")
var serverMode = flag.Bool("server", true, "Run demo server")
var pingCount = flag.Int("n", 5, "Number of client/server pings")
var demoAuth = flag.String("auth", "tao", "\"tcp\", \"tls\", or \"tao\"")
var configPath = flag.String("config", "tao.config", "The Tao domain config")
var ca = flag.String("ca", "", "address for Tao CA, if any")

var subprinRule = "(forall P: forall Hash: TrustedProgramHash(Hash) and Subprin(P, %v, Hash) implies MemberProgram(P))"
var argsRule = "(forall Y: forall P: forall S: MemberProgram(P) and TrustedArgs(S) and Subprin(Y, P, S) implies Authorized(Y, \"Execute\"))"
var demoRule = "TrustedArgs(ext.Args(%s))"


func doClient(domain *tao.Domain) {
	network := "tcp"
	keys, err := tao.NewTemporaryTaoDelegatedKeys(tao.Signing, tao.Parent())
	if err != nil {
		fmt.Printf("client: couldn't generate temporary Tao keys: %s\n", err)
		return
	}

	// TODO(tmroeder): fix the name
	cert, err := keys.SigningKey.CreateSelfSignedX509(&pkix.Name{
		Organization: []string{"Google Tao Demo"}})
	if err != nil {
		fmt.Printf("client: couldn't create a self-signed X.509 cert: %s\n", err)
		return
	}
	// TODO(kwalsh) keys should save cert on disk if keys are on disk
	keys.Cert = cert

	g := domain.Guard
	if *ca != "" {
		na, err := taonet.RequestTruncatedAttestation(network, *ca, keys, domain.Keys.VerifyingKey)
		if err != nil {
			fmt.Printf("client: couldn't get a truncated attestation from %s: %s\n", *ca, err)
			return
		}

		keys.Delegation = na

		// If we're using a CA, then use a custom guard that accepts only
		// programs that have talked to the CA.
		g, err = newTempCAGuard(domain.Keys.VerifyingKey)
		if err != nil {
			fmt.Printf("client: couldn't set up a new guard: %s\n", err)
			return
		}
	}

	pingGood := 0
	pingFail := 0
	for i := 0; i < *pingCount || *pingCount < 0; i++ { // negative means forever
		if doRequest(g, domain, keys) {
			pingGood++
		} else {
			pingFail++
		}
		fmt.Printf("client: made %d connections, finished %d ok, %d bad pings\n",
			i+1, pingGood, pingFail)
	}
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

	// TODO(tmroeder): use the Domain and the tao parent to set up the keys and
	// the guard. Also need to hook the datalog guard into the domain and get
	// the basic tests working with this guard, especially execution
	// authorization.
	serverReady <- true
	serverDone <- true

	domain, err := tao.LoadDomain(*configPath, nil)
	if err != nil {
		fmt.Printf("error: couldn't load the tao domain from %s\n", *configPath)
		return
	}

	ok := <-serverReady
	if ok {
		doClient(domain)
	}
	serverStop <- true
	<-serverDone
	fmt.Printf("Done\n")
}
