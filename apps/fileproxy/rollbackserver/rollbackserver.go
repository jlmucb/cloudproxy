// Copyright (c) 2014, Google Corporation.  All rights reserved.
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
// File: rollbackserver.go

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net"

	"github.com/jlmucb/cloudproxy/apps/fileproxy"
	tao "github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
	"github.com/jlmucb/cloudproxy/util"
)

var hostcfg = flag.String("../hostdomain/tao.config", "../hostdomain/tao.config", "path to host tao configuration")
var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8129", "port for client/server")
var rollbackserverPath = flag.String("rollbackserver_files/", "rollbackserver_files/", "rollbackserver directory")
var serverAddr string

var DerPolicyCert []byte
var SigningKey tao.Keys
var SymKeys []byte
var ProgramCert []byte

func clientServiceThead(ms *util.MessageStream, fileGuard tao.Guard) {
	log.Printf("rollbackserver: clientServiceThead\n")
}

func server(serverAddr string, prin string) {
	var sock net.Listener
	log.Printf("fileserver: server\n")

	/*
		rollbackserverMaster = new(fileproxy.RollbackMaster)
		err := fileserverResourceMaster.InitMaster(*fileserverFilePath, *fileserverPath, prin)
		if err != nil {
			log.Printf("fileserver: can't InitMaster\n")
			return
		}
	*/

	policyCert, err := x509.ParseCertificate(DerPolicyCert)
	if err != nil {
		log.Printf("fileserver: can't ParseCertificate\n")
		return
	}
	pool := x509.NewCertPool()
	pool.AddCert(policyCert)
	tlsc, err := taonet.EncodeTLSCert(&SigningKey)
	if err != nil {
		log.Printf("fileserver, encode error: ", err)
		log.Printf("\n")
		return
	}
	conf := &tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: false, //true,
		ClientAuth:         tls.RequireAnyClientCert,
	}
	log.Printf("Listenting\n")
	sock, err = tls.Listen("tcp", serverAddr, conf)
	// sock, err = net.Listen("tcp", serverAddr)
	if err != nil {
		log.Printf("rollbackserver, listen error: ", err)
		log.Printf("\n")
		return
	}
	for {
		log.Printf("rollbackserver: at Accept\n")
		conn, err := sock.Accept()
		if err != nil {
			log.Printf("rollbackserver: can't accept connection: %s\n", err.Error())
		} else {
			ms := util.NewMessageStream(conn)
			go clientServiceThead(ms, nil)
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
	log.Printf("rollbackserver: Domain name: %s\n", hostDomain.ConfigPath)
	DerPolicyCert = nil
	if hostDomain.Keys.Cert != nil {
		DerPolicyCert = hostDomain.Keys.Cert.Raw
	}
	if DerPolicyCert == nil {
		log.Printf("rollbackserver: can't retrieve policy cert\n")
		return
	}

	e := auth.PrinExt{Name: "rollbackserver_version_1"}
	err = tao.Parent().ExtendTaoName(auth.SubPrin{e})
	if err != nil {
		return
	}

	myTaoName, err := tao.Parent().GetTaoName()
	if err != nil {
		return
	}
	log.Printf("rollbackserver: my name is %s\n", myTaoName)

	sealedSymmetricKey, sealedSigningKey, derCert, delegation, err := fileproxy.GetMyCryptoMaterial(*rollbackserverPath)
	if sealedSymmetricKey == nil || sealedSigningKey == nil || delegation == nil || derCert == nil {
		log.Printf("rollbackserver: No key material present\n")
	}
	ProgramCert = derCert

	defer fileproxy.ZeroBytes(SymKeys)
	if sealedSymmetricKey != nil {
		symkeys, policy, err := tao.Parent().Unseal(sealedSymmetricKey)
		if err != nil {
			return
		}
		if policy != tao.SealPolicyDefault {
			log.Printf("rollbackserver: unexpected policy on unseal\n")
		}
		SymKeys = symkeys
		log.Printf("rollbackserver: Unsealed symKeys: % x\n", SymKeys)
	} else {
		symkeys, err := fileproxy.InitializeSealedSymmetricKeys(*rollbackserverPath, tao.Parent(), 64)
		if err != nil {
			log.Printf("rollbackserver: InitializeSealedSymmetricKeys error: %s\n", err)
		}
		SymKeys = symkeys
		log.Printf("rollbackserver: InitilizedsymKeys: % x\n", SymKeys)
	}

	if sealedSigningKey != nil {
		log.Printf("rollbackserver: retrieving signing key\n")
		signingkey, err := fileproxy.SigningKeyFromBlob(tao.Parent(),
			sealedSigningKey, derCert, delegation)
		if err != nil {
			log.Printf("rollbackserver: SigningKeyFromBlob error: %s\n", err)
		}
		SigningKey = *signingkey
		log.Printf("rollbackserver: Retrieved Signing key: % x\n", SigningKey)
	} else {
		log.Printf("rollbackserver: initializing signing key\n")
		signingkey, err := fileproxy.InitializeSealedSigningKey(*rollbackserverPath,
			tao.Parent(), *hostDomain)
		if err != nil {
			log.Printf("rollbackserver: InitializeSealedSigningKey error: %s\n", err)
		}
		SigningKey = *signingkey
		log.Printf("rollbackserver: Initialized signingKey: % x\n", SigningKey)
		ProgramCert = SigningKey.Cert.Raw
	}
	taoName := myTaoName.String()
	_ = fileproxy.InitProgramPolicy(DerPolicyCert, SigningKey, SymKeys, ProgramCert)

	server(serverAddr, taoName)
	if err != nil {
		log.Printf("rollbackserver: server error\n")
	}
	log.Printf("rollbackserver: done\n")
}
