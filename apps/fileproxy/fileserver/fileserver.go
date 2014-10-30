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
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"

	"github.com/jlmucb/cloudproxy/apps/fileproxy"
	tao "github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
	"github.com/jlmucb/cloudproxy/util"
	// "io/ioutil"
)

var hostcfg = flag.String("../hostdomain/tao.config", "../hostdomain/tao.config", "path to host tao configuration")
var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var fileserverPath = flag.String("./fileserver_files/", "./fileserver_files/", "fileserver directory")
var fileserverFilePath = flag.String("./fileserver_files/stored_files/", "./fileserver_files/stored_files/",
	"fileserver directory")
var serverAddr string
var testFile = flag.String("originalTestFile", "originalTestFile", "test file")

var DerPolicyCert []byte
var SigningKey tao.Keys
var SymKeys []byte
var ProgramCert []byte
var fileserverResourceMaster *fileproxy.ResourceMaster

func clientServiceThead(ms *util.MessageStream, fileGuard tao.Guard) {
	fmt.Printf("fileserver: clientServiceThead\n")
	// How do I know if the connection terminates?
	for {
		fmt.Printf("clientServiceThead: ReadString\n")
		strbytes, err := ms.ReadString()
		if err != nil {
			return
		}
		terminate, err := fileserverResourceMaster.HandleServiceRequest(ms, []byte(strbytes))
		if terminate {
			break
		}
	}
	fmt.Printf("fileserver: client thread terminating\n")
}

func server(serverAddr string, prin string) {
	var sock net.Listener
	fmt.Printf("fileserver: server\n")

	fileserverResourceMaster = new(fileproxy.ResourceMaster)
	err := fileserverResourceMaster.InitMaster(*fileserverFilePath, *fileserverPath, prin)
	if err != nil {
		fmt.Printf("fileserver: can't InitMaster\n")
		return
	}

	policyCert, err := x509.ParseCertificate(DerPolicyCert)
	if err != nil {
		fmt.Printf("fileserver: can't ParseCertificate\n")
		return
	}
	pool := x509.NewCertPool()
	pool.AddCert(policyCert)
	tlsc, err := taonet.EncodeTLSCert(&SigningKey)
	if err != nil {
		fmt.Printf("fileserver, encode error: ", err)
		fmt.Printf("\n")
		return
	}
	conf := &tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: false, //true,
		ClientAuth:         tls.RequireAnyClientCert,
	}
	fmt.Printf("Listenting\n")
	sock, err = tls.Listen("tcp", serverAddr, conf)
	// sock, err = net.Listen("tcp", serverAddr)
	if err != nil {
		fmt.Printf("fileserver, listen error: ", err)
		fmt.Printf("\n")
		return
	}
	for {
		fmt.Printf("server: at Accept\n")
		conn, err := sock.Accept()
		if err != nil {
			fmt.Printf("server: can't accept connection: %s\n", err.Error())
		} else {
			ms := util.NewMessageStream(conn)
			go clientServiceThead(ms, fileserverResourceMaster.Guard)
		}
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
	DerPolicyCert = nil
	if hostDomain.Keys.Cert != nil {
		DerPolicyCert = hostDomain.Keys.Cert.Raw
	}
	if DerPolicyCert == nil {
		fmt.Printf("can't retrieve policy cert\n")
		return
	}

	e := auth.PrinExt{Name: "fileserver_version_1"}
	err = tao.Parent().ExtendTaoName(auth.SubPrin{e})
	if err != nil {
		return
	}

	myTaoName, err := tao.Parent().GetTaoName()
	if err != nil {
		return
	}
	fmt.Printf("fileserver: my name is %s\n", myTaoName)

	sealedSymmetricKey, sealedSigningKey, derCert, delegation, err := fileproxy.GetMyCryptoMaterial(*fileserverPath)
	if sealedSymmetricKey == nil || sealedSigningKey == nil || delegation == nil || derCert == nil {
		fmt.Printf("fileserver: No key material present\n")
	}
	ProgramCert = derCert

	defer fileproxy.ZeroBytes(SymKeys)
	if sealedSymmetricKey != nil {
		symkeys, policy, err := tao.Parent().Unseal(sealedSymmetricKey)
		if err != nil {
			return
		}
		if policy != tao.SealPolicyDefault {
			fmt.Printf("fileserver: unexpected policy on unseal\n")
		}
		SymKeys = symkeys
		fmt.Printf("fileserver: Unsealed symKeys: % x\n", SymKeys)
	} else {
		symkeys, err := fileproxy.InitializeSealedSymmetricKeys(*fileserverPath, tao.Parent(), 64)
		if err != nil {
			fmt.Printf("fileserver: InitializeSealedSymmetricKeys error: %s\n", err)
		}
		SymKeys = symkeys
		fmt.Printf("fileserver: InitilizedsymKeys: % x\n", SymKeys)
	}

	if sealedSigningKey != nil {
		fmt.Printf("retrieving signing key\n")
		signingkey, err := fileproxy.SigningKeyFromBlob(tao.Parent(),
			sealedSigningKey, derCert, delegation)
		if err != nil {
			fmt.Printf("fileserver: SigningKeyFromBlob error: %s\n", err)
		}
		SigningKey = *signingkey
		fmt.Printf("fileserver: Retrieved Signing key: % x\n", SigningKey)
	} else {
		fmt.Printf("initializing signing key\n")
		signingkey, err := fileproxy.InitializeSealedSigningKey(*fileserverPath,
			tao.Parent(), *hostDomain)
		if err != nil {
			fmt.Printf("fileserver: InitializeSealedSigningKey error: %s\n", err)
		}
		SigningKey = *signingkey
		fmt.Printf("fileserver: Initialized signingKey: % x\n", SigningKey)
		ProgramCert = SigningKey.Cert.Raw
	}
	taoName := myTaoName.String()
	_ = fileproxy.InitProgramPolicy(DerPolicyCert, SigningKey, SymKeys, ProgramCert)

	server(serverAddr, taoName)
	if err != nil {
		fmt.Printf("fileserver: server error\n")
	}
	fmt.Printf("fileserver: done\n")
}
