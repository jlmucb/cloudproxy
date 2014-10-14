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
// File: fileserver.go

package main

import (
	"flag"
	"fmt"
	"crypto/tls"
	"crypto/x509"
	"net"

	tao "github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
	"github.com/jlmucb/cloudproxy/apps/fileproxy"
	"github.com/jlmucb/cloudproxy/util"
)

var hostcfg= flag.String("../hostdomain/tao.config", "../hostdomain/tao.config",  "path to host tao configuration")
var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var fileserverPath= flag.String("./fileclient_files/", "./fileclient_files/", "fileclient directory")
var serverAddr string
var testFile= flag.String("stored_files/originalTestFile", "stored_files/originalTestFile", "test file")

var SigningKey tao.Keys
var SymKeys  []byte
var ProgramCert []byte
var fileserverResourceMaster *fileproxy.ResourceMaster

func newTempCAGuard(v tao.Verifier) (tao.Guard, error) {
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


func clientServiceThead(conn net.Conn, verifier tao.Keys, fileGuard *tao.Guard) {
	fmt.Printf("fileserver: clientServiceThead\n")
	// How do I know if the connection terminates?
	ms:= util.NewMessageStream(conn)
	for {
		strbytes,err:= ms.ReadString()
		if(err!=nil) {
			return
		}
		terminate, err:= fileserverResourceMaster.HandleServiceRequest(conn, []byte(strbytes))
		if terminate {
			break;
		}
	}
	fmt.Printf("fileserver: client thread terminating\n")
}

func server(serverAddr string, prin string, verifier tao.Keys, rootCert []byte) error {
	var sock net.Listener

fmt.Printf("server\n")
	// construct nego guard
	connectionGuard, err:= newTempCAGuard(*verifier.VerifyingKey)
	if(err!=nil) {
		fmt.Printf("server: can't create connection guard\n")
		return nil
	}

	// init fileserver data
	fileserverResourceMaster= new(fileproxy.ResourceMaster)
	err= fileserverResourceMaster.InitMaster(*fileserverPath, prin)

	// how do I make the program cert a root?
	// cert, err := x509.ParseCertificate(ProgramCert)
	conf := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		// TODO: Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
	}
	sock, err = taonet.Listen("tls", serverAddr, conf, connectionGuard, verifier.VerifyingKey, SigningKey.Delegation)
	for {
		conn, err := sock.Accept()
		 if err != nil {
			fmt.Printf("server: can't accept connection: %s\n", err.Error())
			return nil
		}
		go clientServiceThead(conn, verifier, fileserverResourceMaster.Guard)
	}
}

func main() {
	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort

	hostDomain, err := tao.LoadDomain(*hostcfg, nil)
	if err != nil {
		return
	}
	fmt.Printf("fileserver: Domain name: %s\n", hostDomain.ConfigPath)

	e := auth.PrinExt{Name: "fileserver.version.1",}
	err = tao.Parent().ExtendTaoName(auth.SubPrin{e})
	if err != nil {
		return
	}

	myTaoName, err := tao.Parent().GetTaoName()
	if(err!=nil) {
		return
	}
	fmt.Printf("fileserver: my name is %s\n", myTaoName)

	sealedSymmetricKey, sealedSigningKey, derCert, delegation, err:= fileproxy.GetMyCryptoMaterial(*fileserverPath) 
	if(sealedSymmetricKey==nil || sealedSigningKey==nil ||delegation== nil || derCert==nil || err==nil) {
		fmt.Printf("fileserver: No key material present\n")
	}
	ProgramCert= derCert

	defer fileproxy.ZeroBytes(SymKeys)
	if(sealedSymmetricKey!=nil) {
		SymKeys, policy, err := tao.Parent().Unseal(sealedSymmetricKey)
		if err != nil {
			return
		}
		if policy != tao.SealPolicyDefault {
			fmt.Printf("fileserver: unexpected policy on unseal\n")
		}
		fmt.Printf("fileserver: Unsealed symKeys: % x\n", SymKeys)
	} else {
		SymKeys, err= fileproxy.InitializeSealedSymmetricKeys(*fileserverPath, tao.Parent(), 64)
		if err != nil {
			fmt.Printf("fileserver: InitializeSealedSymmetricKeys error: %s\n", err)
		}
		fmt.Printf("fileserver: InitilizedsymKeys: % x\n", SymKeys)
	}

	if(sealedSigningKey!=nil) {
		SigningKey, err:= fileproxy.SigningKeyFromBlob(tao.Parent(), 
		sealedSigningKey, derCert, delegation)
		if err != nil {
			fmt.Printf("fileserver: SigningKeyFromBlob error: %s\n", err)
		}
		fmt.Printf("fileserver: Retrieved Signing key: % x\n", SigningKey)
	} else {
		SigningKey, err:=  fileproxy.InitializeSealedSigningKey(*fileserverPath, 
					tao.Parent(), *hostDomain)
		if err != nil {
			fmt.Printf("fileserver: InitializeSealedSigningKey error: %s\n", err)
		}
		fmt.Printf("fileserver: Initilized signingKey: % x\n", SigningKey)
	}
	if err != nil {
		fmt.Printf("fileserver: cant get signing key from blob")
	}
	var rootCert []byte
	rootCert= nil
	// fix rootcert
	err= server(serverAddr, myTaoName.String(), *hostDomain.Keys, rootCert)
	if(err!=nil) {
		fmt.Printf("fileserver: server error")
	}
	fmt.Printf("fileserver: done\n")
}
