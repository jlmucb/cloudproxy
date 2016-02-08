// Copyright (c) 2014, Google, Inc.,  All rights reserved.
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
//
// File: simple.go

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"io/ioutil"
	"log"

	"code.google.com/p/goprotobuf/proto"

	"github.com/jlmucb/cloudproxy/apps/fileproxy"
	tao "github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
	"github.com/jlmucb/cloudproxy/util"
)

var simplecfg = flag.String("../simpledomain/tao.config", "../simpledomain/tao.config",
			"path to tao configuration")
var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var serverAddr string

func main() {

	// This holds the cloudproxy specific data for this program
	// like Program Cert and Program Private key.
	var clientProgramObject simpleexample.ProgramPolicy

	// Parse flags
	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort

	// Load domain info for this domain
	simpleDomain, err := tao.LoadDomain(*hostcfg, nil)
	if err != nil {
		log.Fatalln("fileclient: Can't load domain")
	}

	var derPolicyCert []byte
	if simpleDomain.Keys.Cert != nil {
		derPolicyCert = simpleDomain.Keys.Cert.Raw
	}
	if derPolicyCert == nil {
		log.Fatalln("simpleclient: Can't retrieve policy cert")
	}

	// Extend my name.
	err := simpleDomain.ExtendTaoName(tao.Parent())
	if err != nil {
		log.Fatalln("simpleclient: can't extend the Tao with the policy key")
	}
	e := auth.PrinExt{Name: "simpleclient_version_1"}
	err = tao.Parent().ExtendTaoName(auth.SubPrin{e})
	if err != nil {
		return
	}

	// Retrieve my name.
	taoName, err := tao.Parent().GetTaoName()
	if err != nil {
		log.Fatalln("fileclient: Can't get tao name")
		return
	}
	log.Printf("simpleclient: my name is %s\n", taoName)

	// Get my keys
	sealedSymmetricKey, sealedSigningKey, programCert, delegation, err := simplecommon.LoadProgramKeys(*simpleClientPath)
	if err != nil {
		log.Printf("simpleclient: can't retrieve key material\n")
	}
	if sealedSymmetricKey == nil || sealedSigningKey == nil || delegation == nil || programCert == nil {
		log.Printf("fileclient: No key material present\n")
	}
	log.Printf("simpleclient: Finished fileproxy.LoadProgramKeys\n")

	// Unseal my symmetric keys, or initialize them.
	var symKeys []byte
	if sealedSymmetricKey != nil {
		symKeys, policy, err := tao.Parent().Unseal(sealedSymmetricKey)
		if err != nil {
			return
		}
		if policy != tao.SealPolicyDefault {
			log.Printf("simpleclient: unexpected policy on unseal\n")
		}
		log.Printf("fileclient: Unsealed symKeys: % x\n", symKeys)
	} else {
		symKeys, err := simplecommon.InitializeSealedSymmetricKeys(*simpleClientPath,
			tao.Parent(), simpleclient.SizeofSymmetricKeys)
		if err != nil {
			log.Printf("simpleclient: InitializeSealedSymmetricKeys error: %s\n", err)
		}
		log.Printf("simpleclient: InitilizedsymKeys: % x\n", symKeys)
	}

	// Remember to zero my keys.
	defer simplecommon.ZeroBytes(symKeys)

	// Get my private key if present or initialize them.
	var signingKey *tao.Keys
	if sealedSigningKey != nil {
		signingKey, err = simplecommon.SigningKeyFromBlob(tao.Parent(),
			sealedSigningKey, programCert, delegation)
		if err != nil {
			log.Printf("simpleclient: SigningKeyFromBlob error: %s\n", err)
		}
		log.Printf("simpleclient: Retrieved Signing key: % x\n", *signingKey)
	} else {
		signingKey, err = fileproxy.InitializeSealedSigningKey(*fileclientPath,
			tao.Parent(), *simpleDomain)
		if err != nil {
			log.Printf("simpleclient: InitializeSealedSigningKey error: %s\n", err)
		}
		log.Printf("simpleclient: Initilized signingKey\n")
	}

	// Get the program cert.
	_ = clientProgramObject.InitProgramPolicy(derPolicyCert, taoName.String(), *signingKey,
		symKeys, programCert)

	// Parse policy cert and make it the root of our heierarchy.
	policyCert, err := x509.ParseCertificate(derPolicyCert)
	if err != nil {
		log.Fatalln("fileclient:can't ParseCertificate")
		return
	}
	pool := x509.NewCertPool()
	pool.AddCert(policyCert)

	// Open the Cloudproxy channel.
	tlsc, err := taonet.EncodeTLSCert(signingKey)
	if err != nil {
		log.Printf("simpleclient, encode error: ", err)
		log.Printf("\n")
		return
	}
	conn, err := tls.Dial("tcp", serverAddr, &tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: false,
	})
	if err != nil {
		log.Printf("simpleclient: can't establish channel ", err)
		log.Printf("\n")
		return
	}
	ms := util.NewMessageStream(conn)
	log.Printf("simpleclient: Established channel\n")

	// Get Tao name of Server.

	// Send a simple request and get response.
	/*
	rule := "Delegate(\"jlm\", \"tom\", \"getfile\",\"myfile\")"
	log.Printf("fileclient, sending rule: %s\n", rule)
	err = fileproxy.SendRule(ms, rule, userCert)
	if err != nil {
		log.Printf("fileclient: can't create file\n")
		return
	}
	status, message, size, err := fileproxy.GetResponse(ms)
	if err != nil {
		log.Printf("simpleclient: Error in response to SendCreate\n")
		return
	}
	log.Printf("Response to SendCreate\n")
	fileproxy.PrintResponse(status, message, size)
	if *status != "succeeded" {
		return
	}
	*/

	log.Printf("simpleclient: Done\n")
}
