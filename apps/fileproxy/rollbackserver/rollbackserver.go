// Copyright (c) 2014, Google, Inc.  All rights reserved.
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

func clientServiceThead(ms *util.MessageStream, clientName string, rollbackPolicy *fileproxy.ProgramPolicy, rollbackMasterTable *fileproxy.RollbackMaster) {
	log.Printf("rollbackserver: clientServiceThead\n")
	pi := rollbackMasterTable.AddRollbackProgramTable(clientName)
	if pi == nil {
		log.Printf("rollbackserver cannot rollbackMasterTable.AddRollbackProgramTable\n")
		return
	}
	// How do I know if the connection terminates?
	for {
		log.Printf("clientServiceThead: ReadString\n")
		strbytes, err := ms.ReadString()
		if err != nil {
			return
		}
		terminate, err := rollbackMasterTable.HandleServiceRequest(ms, rollbackPolicy, clientName, []byte(strbytes))
		if terminate {
			break
		}
	}
	log.Printf("fileserver: client thread terminating\n")
}

func server(serverAddr string, prin string, rollbackPolicy *fileproxy.ProgramPolicy, rollbackMasterTable *fileproxy.RollbackMaster) {
	var sock net.Listener
	log.Printf("fileserver: server\n")

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
		InsecureSkipVerify: false,
		ClientAuth:         tls.RequireAnyClientCert,
	}
	log.Printf("Listenting\n")
	sock, err = tls.Listen("tcp", serverAddr, conf)
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
		}
		var clientName string
		clientName = "XYZZY"
		err = conn.(*tls.Conn).Handshake()
		if err != nil {
			log.Printf("TLS handshake failed\n")
		}
		peerCerts := conn.(*tls.Conn).ConnectionState().PeerCertificates
		if peerCerts == nil {
			log.Printf("rollbackserver: can't get peer list\n")
		} else {
			peerCert := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
			if peerCert.Raw == nil {
				log.Printf("rollbackserver: can't get peer name\n")
			} else {
				if peerCert.Subject.OrganizationalUnit != nil {
					clientName = peerCert.Subject.OrganizationalUnit[0]
				}
			}
		}
		log.Printf("rollbackserver, peer name: %s\n", clientName)
		ms := util.NewMessageStream(conn)
		go clientServiceThead(ms, clientName, rollbackPolicy, rollbackMasterTable)
	}
}

func main() {
	log.Printf("rollback server\n")

	var rollbackMaster fileproxy.RollbackMaster
	var RollbackMaster *fileproxy.RollbackMaster
	var rollbackProgramPolicyObject fileproxy.ProgramPolicy
	var RollbackProgramPolicyObject *fileproxy.ProgramPolicy
	RollbackMaster = &rollbackMaster
	RollbackProgramPolicyObject = &rollbackProgramPolicyObject

	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort

	hostDomain, err := tao.LoadDomain(*hostcfg, nil)
	if err != nil {
		log.Fatalln("rollbackserver: can't LoadDomain\n")
	}
	log.Printf("rollbackserver: Domain name: %s\n", hostDomain.ConfigPath)
	DerPolicyCert = nil
	if hostDomain.Keys.Cert != nil {
		DerPolicyCert = hostDomain.Keys.Cert.Raw
	}
	if DerPolicyCert == nil {
		log.Fatalln("rollbackserver: can't retrieve policy cert")
	}

	if err := hostDomain.ExtendTaoName(tao.Parent()); err != nil {
		log.Fatalln("fileserver: can't extend the Tao with the policy key")
	}
	e := auth.PrinExt{Name: "rollbackserver_version_1"}
	err = tao.Parent().ExtendTaoName(auth.SubPrin{e})
	if err != nil {
		log.Fatalln("rollbackserver: can't extend name")
	}

	taoName, err := tao.Parent().GetTaoName()
	if err != nil {
		return
	}
	log.Printf("rollbackserver: my name is %s\n", taoName)

	sealedSymmetricKey, sealedSigningKey, derCert, delegation, err := fileproxy.LoadProgramKeys(*rollbackserverPath)
	if err != nil {
		log.Printf("rollbackserver: can't retrieve key material\n")
	}
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
		symkeys, err := fileproxy.InitializeSealedSymmetricKeys(*rollbackserverPath, tao.Parent(), fileproxy.SizeofSymmetricKeys)
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
		log.Printf("rollbackserver: Initialized signingKey\n")
		ProgramCert = SigningKey.Cert.Raw
	}
	taoNameStr := taoName.String()
	_ = RollbackProgramPolicyObject.InitProgramPolicy(DerPolicyCert, taoNameStr, SigningKey, SymKeys, ProgramCert)
	RollbackMaster.InitRollbackMaster(taoNameStr)

	server(serverAddr, taoNameStr, RollbackProgramPolicyObject, RollbackMaster)
	if err != nil {
		log.Printf("rollbackserver: server error\n")
	}
	log.Printf("rollbackserver: done\n")
}
