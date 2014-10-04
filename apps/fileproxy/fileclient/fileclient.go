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
	"errors"
	"flag"
	"fmt"
	"time"
	"io/ioutil"
	"code.google.com/p/goprotobuf/proto"
	"os"
	//"bufio"
	//"crypto/tls"
	"crypto/x509"
	// "crypto/x509/pkix"
	// "crypto/rand"
	//"net"
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


func InitKeys(path string) ([]byte, *tao.Keys, error) {
	initialTaoPrin, err := tao.Parent().GetTaoName()
	if(err!=nil) {
		return nil, nil, err
	}
	fmt.Printf("My root name is %s\n", initialTaoPrin)

	e := auth.PrinExt{Name: "fileclient.version.1",}
	err = tao.Parent().ExtendTaoName(auth.SubPrin{e})
	if err != nil {
		return nil, nil, err
	}

	myTaoPrin, err := tao.Parent().GetTaoName()
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("My full name is %s\n", myTaoPrin)

	// generate my symmetric keys
	unsealed, err := tao.Parent().GetRandomBytes(128)
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("Symmetric key: % x\n", unsealed)
	sealed, err := tao.Parent().Seal(unsealed, tao.SealPolicyDefault)
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("Sealed bytes  : % x\n", sealed)
	ioutil.WriteFile(path+"sealedKeys", sealed, os.ModePerm)

	// generate signing key
	k:= &tao.Keys{};
	var keyTypes tao.KeyType
	keyTypes=  tao.Signing
	k.SetMyKeyPath(path)
	k.SetKeyType(keyTypes)
	k.SigningKey, err = tao.GenerateSigner()

	details := tao.X509Details {
		Country: "US",
		Organization: "Google",
		CommonName: myTaoPrin.String(), }
	subjectname:= tao.NewX509Name(details)

	der, err := k.SigningKey.CreateSelfSignedDER(subjectname)
	if(err!=nil) {
		fmt.Printf("cant create der\n")
		return nil, nil, err
	}
	fmt.Printf("der: % x\n", der);
	fmt.Printf("\n")
	cert, err := x509.ParseCertificate(der)

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

	k.Cert= cert

	// get it signed by keynegoserver
	// keyNegoAttest, err:= RequestTruncatedAttestation(network, *ca, keys, domain.Keys.VerifyingKey)

	// Save signing key and cert
	// SignedkeyNegoSignedDER:=
	// serSigner:= k.SigningKey.MarshalSignerDER()
	// MarshalSignerProto(s *Signer)
	//ioutil.WriteFile(path+"signer", serSigner, os.ModePerm)
	//ioutil.WriteFile(path+"cert", serCert, os.ModePerm)

	return  unsealed, k, nil
}

func GetBlobs(path string) ([]byte, *x509.Certificate, []byte, error) {
	sealed, err := ioutil.ReadFile(path+"sealedKeys")
	if(err!=nil) {
		return nil, nil, nil, err
	}
	serializedSealedSigning, err := ioutil.ReadFile(path+"signer")
	if(err!=nil) {
		return nil, nil, nil, err
	}
	serializedCert, err := ioutil.ReadFile(path+"cert")
	if(err!=nil) {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(serializedCert)
	if(err!=nil) {
		return nil, nil, nil, err
	}
	return  sealed, cert, serializedSealedSigning, nil
}


func GetMyKeys(path string) ([]byte, *tao.Keys, error) {
	// fetch sealed sym key blob
	sealed, cert, sealedSigning, err := GetBlobs(*fileclientKeypath)
	if(err!=nil) {
		return (InitKeys(path))
	}
	unsealed, policy, err := tao.Parent().Unseal(sealed)
	if err != nil {
		return nil, nil, err
	}
	if policy != tao.SealPolicyDefault {
		return nil, nil, errors.New("unexpected policy on unseal")
	}
	fmt.Printf("got unsealed symmetric keys: % x\n", unsealed)
	signing, policy, err := tao.Parent().Unseal(sealedSigning)
	if err != nil {
		return nil, nil, err
	}
	if policy != tao.SealPolicyDefault {
		return nil, nil, errors.New("unexpected policy on unseal")
	}
	fmt.Printf("got unsealed signing key: % x\n", )

	signingKey:= &tao.Keys{}
	signingKey.Cert= cert
	signingKey.SigningKey, err= tao.UnmarshalSignerDER(signing)
	if err != nil {
		return nil, nil, err
	}
	return unsealed, signingKey, nil
}

func main() {
	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort

	// it I can't get my keys, init
	symkeys, sigkey, err:= GetMyKeys(*fileclientKeypath);
	if err != nil {
		fmt.Printf("error: couldn't GetMyKeys\n")
		return
	}
	return
	if(symkeys== nil) {
		// placeholder
		return
	}
	if(sigkey== nil) {
		// placeholder
		return
	}

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
