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
// File: fileserver.go

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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
var serverPort = flag.String("port", "8123", "port for client/server")
var fileserverPath = flag.String("fileserver_files/", "fileserver_files/", "fileserver directory")
var fileserverFilePath = flag.String("fileserver_files/stored_files/", "fileserver_files/stored_files/",
	"fileserver directory")
var serverAddr string
var testFile = flag.String("originalTestFile", "originalTestFile", "test file")

func clientServiceThead(ms *util.MessageStream, clientProgramName string, fileServerProgramPolicy *fileproxy.ProgramPolicy, resourceMaster *fileproxy.ResourceMaster) {
	log.Printf("fileserver: clientServiceThead\n")

	// How do I know if the connection terminates?
	for {
		log.Printf("clientServiceThead: ReadString\n")
		strbytes, err := ms.ReadString()
		if err != nil {
			return
		}
		terminate, err := resourceMaster.HandleServiceRequest(ms, fileServerProgramPolicy, clientProgramName, []byte(strbytes))
		if terminate {
			break
		}
	}
	log.Printf("fileserver: client thread terminating\n")
}

func server(serverAddr string, prin string, derPolicyCert []byte, signingKey *tao.Keys, fileServerProgramPolicy *fileproxy.ProgramPolicy, fileServerResourceMaster *fileproxy.ResourceMaster) {
	var sock net.Listener
	log.Printf("fileserver: server\n")

	err := fileServerResourceMaster.InitMaster(*fileserverFilePath, *fileserverPath, prin)
	if err != nil {
		log.Printf("fileserver: can't InitMaster\n")
		return
	}

	policyCert, err := x509.ParseCertificate(derPolicyCert)
	if err != nil {
		log.Printf("fileserver: can't ParseCertificate\n")
		return
	}
	pool := x509.NewCertPool()
	pool.AddCert(policyCert)
	tlsc, err := taonet.EncodeTLSCert(signingKey)
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
	log.Printf("Listening\n")
	sock, err = tls.Listen("tcp", serverAddr, conf)
	if err != nil {
		log.Printf("fileserver, listen error: ", err)
		log.Printf("\n")
		return
	}
	for {
		log.Printf("fileserver: at Accept\n")
		conn, err := sock.Accept()
		if err != nil {
			log.Printf("fileserver: can't accept connection: %s\n", err.Error())
		} else {
			var clientName string
			clientName = "XYZZY"
			err = conn.(*tls.Conn).Handshake()
			if err != nil {
				log.Printf("TLS handshake failed\n")
			}
			peerCerts := conn.(*tls.Conn).ConnectionState().PeerCertificates
			if peerCerts == nil {
				log.Printf("fileserver: can't get peer list\n")
			} else {
				peerCert := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
				if peerCert.Raw == nil {
					log.Printf("fileserver: can't get peer name\n")
				} else {
					if peerCert.Subject.OrganizationalUnit != nil {
						clientName = peerCert.Subject.OrganizationalUnit[0]
					}
				}
			}
			log.Printf("fileserver, peer name: %s\n", clientName)
			ms := util.NewMessageStream(conn)
			go clientServiceThead(ms, clientName, fileServerProgramPolicy, fileServerResourceMaster)
		}
	}
}

func main() {

	var fileServerResourceMaster fileproxy.ResourceMaster
	var FileServerResourceMaster *fileproxy.ResourceMaster
	var fileServerProgramPolicy fileproxy.ProgramPolicy
	var FileServerProgramPolicy *fileproxy.ProgramPolicy

	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort

	hostDomain, err := tao.LoadDomain(*hostcfg, nil)
	if err != nil {
		return
	}
	log.Printf("fileserver: Domain name: %s\n", hostDomain.ConfigPath)
	var derPolicyCert []byte
	if hostDomain.Keys.Cert != nil {
		derPolicyCert = hostDomain.Keys.Cert.Raw
	}
	if derPolicyCert == nil {
		log.Printf("fileserver: can't retrieve policy cert\n")
		return
	}

	/*
	 Replace with: hostDomai.ExtendTaoDomain(tao)
	*/
	sha256Hash := sha256.New()
	sha256Hash.Write(derPolicyCert)
	policyCertHash := sha256Hash.Sum(nil)
	hexCertHash := hex.EncodeToString(policyCertHash)
	e := auth.PrinExt{Name: hexCertHash}
	err = tao.Parent().ExtendTaoName(auth.SubPrin{e})
	if err != nil {
		return
	}

	e = auth.PrinExt{Name: "fileserver_version_1"}
	err = tao.Parent().ExtendTaoName(auth.SubPrin{e})
	if err != nil {
		return
	}

	taoName, err := tao.Parent().GetTaoName()
	if err != nil {
		log.Printf("fileserver: cant get tao name\n")
		return
	}
	log.Printf("fileserver: my name is %s\n", taoName)

	var programCert []byte
	sealedSymmetricKey, sealedSigningKey, programCert, delegation, err := fileproxy.LoadProgramKeys(*fileserverPath)
	if err != nil {
		log.Printf("fileserver: cant retrieve key material\n")
	}
	if sealedSymmetricKey == nil || sealedSigningKey == nil || delegation == nil || programCert == nil {
		log.Printf("fileserver: No key material present\n")
	}

	var symKeys []byte
	defer fileproxy.ZeroBytes(symKeys)
	if sealedSymmetricKey != nil {
		symKeys, policy, err := tao.Parent().Unseal(sealedSymmetricKey)
		if err != nil {
			return
		}
		if policy != tao.SealPolicyDefault {
			log.Printf("fileserver: unexpected policy on unseal\n")
		}
		log.Printf("fileserver: Unsealed symKeys: % x\n", symKeys)
	} else {
		symKeys, err = fileproxy.InitializeSealedSymmetricKeys(*fileserverPath, tao.Parent(), fileproxy.SizeofSymmetricKeys)
		if err != nil {
			log.Printf("fileserver: InitializeSealedSymmetricKeys error: %s\n", err)
		}
		log.Printf("fileserver: InitilizedsymKeys: % x\n", symKeys)
	}

	var signingKey *tao.Keys
	if sealedSigningKey != nil {
		log.Printf("retrieving signing key\n")
		signingKey, err = fileproxy.SigningKeyFromBlob(tao.Parent(),
			sealedSigningKey, programCert, delegation)
		if err != nil {
			log.Printf("fileserver: SigningKeyFromBlob error: %s\n", err)
		}
		log.Printf("fileserver: Retrieved Signing key: % x\n", *signingKey)
	} else {
		log.Printf("fileserver: initializing signing key\n")
		signingKey, err = fileproxy.InitializeSealedSigningKey(*fileserverPath,
			tao.Parent(), *hostDomain)
		if err != nil {
			log.Printf("fileserver: InitializeSealedSigningKey error: %s\n", err)
		}
		log.Printf("fileserver: Initialized signingKey\n")
		programCert = signingKey.Cert.Raw
	}
	taoNameStr := taoName.String()

	FileServerProgramPolicy = &fileServerProgramPolicy
	FileServerResourceMaster = &fileServerResourceMaster
	_ = FileServerProgramPolicy.InitProgramPolicy(derPolicyCert, taoNameStr, *signingKey, symKeys, programCert)

	server(serverAddr, taoNameStr, derPolicyCert, signingKey, FileServerProgramPolicy, FileServerResourceMaster)
	if err != nil {
		log.Printf("fileserver: server error\n")
	}
	log.Printf("fileserver: done\n")
}
