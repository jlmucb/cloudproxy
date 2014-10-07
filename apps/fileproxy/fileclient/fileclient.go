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
	//"errors"
	"flag"
	"fmt"
	//"time"
	//"io/ioutil"
	//"code.google.com/p/goprotobuf/proto"
	//"os"
	//"bufio"
	//"crypto/tls"
	//"crypto/x509"
	// "crypto/x509/pkix"
	// "crypto/rand"
	//"net"
	//"strings"

	tao "github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	// taonet "github.com/jlmucb/cloudproxy/tao/net"
	"github.com/jlmucb/cloudproxy/apps/fileproxy"
)

var hostcfg= flag.String("../hostdomain/tao.config", "../hostdomain/tao.config",  "path to host tao configuration")
var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var fileclientPath= flag.String("./fileclient_files/", "./fileclient_files/", "fileclient directory")
var serverAddr string


func main() {
	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort

	host_domain, err := tao.LoadDomain(*hostcfg, nil)
	if err != nil {
		return
	}
	fmt.Printf("Domain name: %s\n", host_domain.ConfigPath)

	e := auth.PrinExt{Name: "fileclient.version.1",}
	err = tao.Parent().ExtendTaoName(auth.SubPrin{e})
	if err != nil {
		return
	}

	myTaoName, err := tao.Parent().GetTaoName()
	if(err!=nil) {
		return
	}
	fmt.Printf("fileclient: my name is %s\n", myTaoName)

	var der_cert []byte
	sealedSymmetricKey, sealedSigningKey, der_cert, err:= fileproxy.GetMyCryptoMaterial(*fileclientPath) 
	if(sealedSymmetricKey==nil || sealedSigningKey==nil || der_cert==nil || err==nil) {
		fmt.Printf("No key material present\n")
	}

	var symKeys []byte;
	// defer zeroBytes(symKeys)
	if(sealedSymmetricKey!=nil) {
		symKeys, policy, err := tao.Parent().Unseal(sealedSymmetricKey)
		if err != nil {
			return
		}
		if policy != tao.SealPolicyDefault {
			fmt.Printf("fileclient: unexpected policy on unseal\n")
		}
		fmt.Printf("Unsealed symKeys: % x\n", symKeys)
	} else {
		symKeys, err= fileproxy.InitializeSealedSymmetricKeys(*fileclientPath, tao.Parent(), 64)
		if err != nil {
			fmt.Printf("fileclient: InitializeSealedSymmetricKeys error: %s\n", err)
		}
		fmt.Printf("InitilizedsymKeys: % x\n", symKeys)
	}

	var  signingKeyBlob []byte
	// defer zeroBytes(signingKeyBlob)
	if(sealedSigningKey!=nil) {
		signingKeyBlob, policy, err := tao.Parent().Unseal(sealedSigningKey)
		if err != nil {
			fmt.Printf("fileclient: symkey unsealing error: %s\n")
		}
		if policy != tao.SealPolicyDefault {
			fmt.Printf("fileclient: unexpected policy on unseal\n")
		}
		fmt.Printf("Unsealed Signing Key blob: % x\n", signingKeyBlob)
	} else {
		signingKeyBlob, der_cert,err=  fileproxy.InitializeSealedSigningKey(*fileclientPath, tao.Parent())
		if err != nil {
			fmt.Printf("fileclient: InitializeSealedSigningKey error: %s\n", err)
		}
		fmt.Printf("Initilized signingKey: % x\n", signingKeyBlob)
	}
	fmt.Printf("Signing cert: % x\n",  der_cert)

	fmt.Printf("fileclient: Done\n")
}
