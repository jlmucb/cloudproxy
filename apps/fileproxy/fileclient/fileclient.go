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
	// "net"

	tao "github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	"github.com/jlmucb/cloudproxy/apps/fileproxy"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
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
)

var hostcfg= flag.String("../hostdomain/tao.config", "../hostdomain/tao.config",  "path to host tao configuration")
var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var fileclientPath= flag.String("./fileclient_files/", "./fileclient_files/", "fileclient directory")
var serverAddr string
var testFilePath= flag.String("stored_files/", "stored_files/", "file path")
var testFile= flag.String("stored_files/originalTestFile", "stored_files/originalTestFile", "test file")

var SigningKey tao.Keys
var SymKeys  []byte
var ProgramCert []byte

func newTempCAGuard() (tao.Guard, error) {
	fmt.Printf("fileserver: newTempCAGuard\n")
	/*
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
	*/
	g:= tao.LiberalGuard
	return g, nil
}

func main() {
	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort

	hostDomain, err := tao.LoadDomain(*hostcfg, nil)
	if err != nil {
		return
	}
	fmt.Printf("fileclient: Domain name: %s\n", hostDomain.ConfigPath)

	e := auth.PrinExt{Name: "fileclient_version_1",}
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
	if(sealedSymmetricKey==nil || sealedSigningKey==nil || delegation== nil || derCert==nil) {
		fmt.Printf("fileclient: No key material present\n")
	}
	ProgramCert= derCert

	defer fileproxy.ZeroBytes(SymKeys)
	if(sealedSymmetricKey!=nil) {
		symkeys, policy, err := tao.Parent().Unseal(sealedSymmetricKey)
		if err != nil {
			return
		}
		if policy != tao.SealPolicyDefault {
			fmt.Printf("fileclient: unexpected policy on unseal\n")
		}
		SymKeys= symkeys
		fmt.Printf("fileclient: Unsealed symKeys: % x\n", SymKeys)
	} else {
		symkeys, err:= fileproxy.InitializeSealedSymmetricKeys(*fileclientPath, tao.Parent(), 64)
		if err != nil {
			fmt.Printf("fileclient: InitializeSealedSymmetricKeys error: %s\n", err)
		}
		SymKeys= symkeys
		fmt.Printf("fileclient: InitilizedsymKeys: % x\n", SymKeys)
	}

	if(sealedSigningKey!=nil) {
		signingkey, err:= fileproxy.SigningKeyFromBlob(tao.Parent(),
		sealedSigningKey, derCert, delegation)
		if err != nil {
			fmt.Printf("fileclient: SigningKeyFromBlob error: %s\n", err)
		}
		SigningKey= *signingkey
		fmt.Printf("fileclient: Retrieved Signing key: % x\n", SigningKey)
	} else {
		signingkey, err:=  fileproxy.InitializeSealedSigningKey(*fileclientPath,
					tao.Parent(), *hostDomain)
		if err != nil {
			fmt.Printf("fileclient: InitializeSealedSigningKey error: %s\n", err)
		}
		SigningKey= *signingkey
		fmt.Printf("fileclient: Initilized signingKey: % x\n", SigningKey)
	}

	var  creds []byte
	creds= []byte("I am a fake cred")
	guard, err:= newTempCAGuard()
	if(err!=nil) {
		fmt.Printf("fileclient:cant construct channel guard\n")
		return;
	}
	if(guard==nil) {
		fmt.Printf("fileclient: guard is nil\n");
	}
	conn, err:= taonet.DialTLSWithKeys("tcp", serverAddr, &SigningKey)
	if(err!=nil) {
		fmt.Printf("fileclient:cant establish channel\n", err)
		fmt.Printf("\n")
		return;
	}
	fmt.Printf("Established channel\n")
	// create a file
	sentFileName:= *fileclientPath+*testFile
	fmt.Printf("fileclient, Creating: %s\n", sentFileName)
	err= fileproxy.SendCreateFile(conn, creds, sentFileName);
	if err != nil {
		fmt.Printf("fileclient: cant create file\n")
		return
	}
	return
	fmt.Printf("fileclient: Sending: %s\n", sentFileName)
	err= fileproxy.SendFile(conn, creds, sentFileName, nil);
	if err != nil {
		fmt.Printf("fileclient: cant send file\n")
		return
	}
	fmt.Printf("fileclient: Getting: %s\n", sentFileName+".received")
	err= fileproxy.GetFile(conn, creds, sentFileName, nil);
	if err != nil {
		fmt.Printf("fileclient: cant send file\n")
		return
	}
	fmt.Printf("fileclient: Done\n")
}
