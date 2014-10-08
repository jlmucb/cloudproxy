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
//
// File: fileclient.go

package main

import (
	"flag"
	"fmt"
	"net"
	//"errors"
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
var testFile= flag.String("stored_files/originalTestFile", "stored_files/originalTestFile", "test file")

var SigningKey tao.Keys
var SymKeys  []byte
var ProgramCert []byte


func main() {
	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort

	hostDomain, err := tao.LoadDomain(*hostcfg, nil)
	if err != nil {
		return
	}
	fmt.Printf("Domain name: %s\n", hostDomain.ConfigPath)

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

	sealedSymmetricKey, sealedSigningKey, derCert, delegation, err:= fileproxy.GetMyCryptoMaterial(*fileclientPath) 
	if(sealedSymmetricKey==nil || sealedSigningKey==nil ||delegation== nil || derCert==nil || err==nil) {
		fmt.Printf("No key material present\n")
	}
	ProgramCert= derCert

	defer fileproxy.ZeroBytes(SymKeys)
	if(sealedSymmetricKey!=nil) {
		SymKeys, policy, err := tao.Parent().Unseal(sealedSymmetricKey)
		if err != nil {
			return
		}
		if policy != tao.SealPolicyDefault {
			fmt.Printf("fileclient: unexpected policy on unseal\n")
		}
		fmt.Printf("Unsealed symKeys: % x\n", SymKeys)
	} else {
		SymKeys, err= fileproxy.InitializeSealedSymmetricKeys(*fileclientPath, tao.Parent(), 64)
		if err != nil {
			fmt.Printf("fileclient: InitializeSealedSymmetricKeys error: %s\n", err)
		}
		fmt.Printf("InitilizedsymKeys: % x\n", SymKeys)
	}

	if(sealedSigningKey!=nil) {
		SigningKey, err:= fileproxy.SigningKeyFromBlob(tao.Parent(), 
		sealedSigningKey, derCert, delegation)
		if err != nil {
			fmt.Printf("fileclient: SigningKeyFromBlob error: %s\n", err)
		}
		fmt.Printf("Retrieved Signing key: % x\n", SigningKey)
	} else {
		SigningKey, err:=  fileproxy.InitializeSealedSigningKey(*fileclientPath, 
					tao.Parent(), *hostDomain)
		if err != nil {
			fmt.Printf("fileclient: InitializeSealedSigningKey error: %s\n", err)
		}
		fmt.Printf("Initilized signingKey: % x\n", SigningKey)
	}
	// establish channel
	var conn net.Conn
	var  creds []byte
	creds= nil
	conn, err= fileproxy.EstablishPeerChannel(tao.Parent(), SigningKey)
	// create a file
	sentFileName:= *fileclientPath+*testFile
	fmt.Printf("Creating: %s\n", sentFileName)
	err= fileproxy.CreateFile(conn, creds, sentFileName);
	if err != nil {
		fmt.Printf("fileclient: cant create file")
	}
	fmt.Printf("Sending: %s\n", sentFileName)
	err= fileproxy.SendFile(conn, creds, sentFileName, nil);
	if err != nil {
		fmt.Printf("fileclient: cant send file")
	}
	fmt.Printf("Getting: %s\n", sentFileName+".received")
	err= fileproxy.GetFile(conn, creds, sentFileName, nil);
	if err != nil {
		fmt.Printf("fileclient: cant send file")
	}
	fmt.Printf("fileclient: Done\n")
}
