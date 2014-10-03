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
	//"bufio"
	//"crypto/tls"
	// "crypto/x509"
	// "crypto/rand"
	// "crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"time"
	"io/ioutil"
	"code.google.com/p/goprotobuf/proto"
	//"net"
	"os"
	//"strings"

	tao "github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	// taonet "github.com/jlmucb/cloudproxy/tao/net"
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

var fileclientKeypath= flag.String("fileclient/path", "keys/",  "path to keys")

var subprinRule = "(forall P: forall Hash: TrustedProgramHash(Hash) and Subprin(P, %v, Hash) implies MemberProgram(P))"
var argsRule = "(forall Y: forall P: forall S: MemberProgram(P) and TrustedArgs(S) and Subprin(Y, P, S) implies Authorized(Y, \"Execute\"))"
var demoRule = "TrustedArgs(ext.Args(%s))"

/*
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
*/


func InitKeys() error {
	initialTaoPrin, err := tao.Parent().GetTaoName()
	if(err!=nil) {
		return err
	}
	fmt.Printf("My root name is %s\n", initialTaoPrin)

	e := auth.PrinExt{Name: "fileclient.version.1",}
	err = tao.Parent().ExtendTaoName(auth.SubPrin{e})
	if err != nil {
		return err
	}

	myTaoPrin, err := tao.Parent().GetTaoName()
	if err != nil {
		return err
	}
	fmt.Printf("My full name is %s\n", myTaoPrin)

	// TODO: fix
	k:= &tao.Keys{};
	var keyTypes tao.KeyType
	keyTypes=  tao.Signing
	k.SetMyKeyPath(*fileclientKeypath)
	k.SetKeyType(keyTypes)
	k.SigningKey, err = tao.GenerateSigner()

	// generate a self signed cert for keynegoserver
	details := tao.X509Details {
		Country: "US",
		Organization: "Google",
		CommonName: myTaoPrin.String(), }
	subjectname:= tao.NewX509Name(details)

	der, err := k.SigningKey.CreateSelfSignedDER(subjectname)
	if(err!=nil) {
		fmt.Printf("cant create der\n")
	}
	fmt.Printf("der: % x\n", der);
	fmt.Printf("\n")
	ioutil.WriteFile(*fileclientKeypath+"certreq", der, os.ModePerm)

	// generate my symmetric keys
	random, err := tao.Parent().GetRandomBytes(128)
	if err != nil {
		return err
	}
	fmt.Printf("Random bytes  : % x\n", random)
	sealed, err := tao.Parent().Seal(random, tao.SealPolicyDefault)
	if err != nil {
		return err
	}
	fmt.Printf("Sealed bytes  : % x\n", sealed)
	ioutil.WriteFile(*fileclientKeypath+"sealedKeys", sealed, os.ModePerm)

	subject:= k.SigningKey.ToPrincipal()
	keySpeaksfor := auth.Speaksfor{
		Delegate:  subject,
		Delegator: myTaoPrin,
	}
	startTime:= time.Now()
	endTime:= startTime.Add(365 * 24 * time.Hour)
	intStart:= startTime.UnixNano()
	intEnd:= endTime.UnixNano()
	attest, err:= tao.Parent().Attest(nil, &intStart, &intEnd, keySpeaksfor)
	if (err==nil) {
		statement:= proto.CompactTextString(attest)
		fmt.Printf("Attest worked\n%s\n", statement)
	} else {
		fmt.Printf("Attest failed\n")
	}

	// get it signed by keynegoserver


	// store the keys and certs

	// for now, we don't init tao in this layer and just use the keys

	return nil
}

func GetBlob() ([]byte, error) {
	// read key blobs and cert.  If not there, return nil
	err:= InitKeys()
	return nil,err 
}

func GetMyKeys() error {
	// fetch sealed blob
	sealed, err := GetBlob()
	return err
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

	// it I can't get my keys, init
	err:= GetMyKeys();
	if err != nil {
		fmt.Printf("error: couldn't GetMyKeys\n")
		return
	}
	return

/*
	ok := <-serverReady
	if ok {
		doClient(domain)
	}
	serverStop <- true
	<-serverDone
 */
	fmt.Printf("Done\n")
}
