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
// File: simpleserver.go

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
var serverPort = flag.String("port", "8123", "port for client/server")
var fileserverFilePath = flag.String("fileserver_files/stored_files/", "fileserver_files/stored_files/",
	"fileserver directory")
var serverAddr string

func serviceThead(ms *util.MessageStream, clientProgramName string,
		serverProgramPolicy *simplecommon.ProgramPolicy) {
	log.Printf("simpleserver: clientServiceThead\n")

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
	log.Printf("simpleserver: client thread terminating\n")
}

func server(serverAddr string, prin string, derPolicyCert []byte, signingKey *tao.Keys,
	serverProgramPolicy *simplecommon.ProgramPolicy) {
	var sock net.Listener
	log.Printf("simpleserver: server\n")

	// Setup Policy root for verify.
	policyCert, err := x509.ParseCertificate(derPolicyCert)
	if err != nil {
		log.Printf("simpleserver: can't ParseCertificate\n")
		return
	}
	pool := x509.NewCertPool()
	pool.AddCert(policyCert)

	tlsc, err := taonet.EncodeTLSCert(signingKey)
	if err != nil {
		log.Printf("simpleserver, encode error: ", err)
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
		log.Printf("simpleserver, listen error: ", err)
		log.Printf("\n")
		return
	}

	// Service client connections.
	for {
		log.Printf("simpleserver: at Accept\n")
		conn, err := sock.Accept()
		if err != nil {
			log.Printf("simpleserver: can't accept connection: %s\n", err.Error())
		} else {
			var clientName string
			clientName = "XYZZY"
			err = conn.(*tls.Conn).Handshake()
			if err != nil {
				log.Printf("simpleserver: TLS handshake failed\n")
			}
			peerCerts := conn.(*tls.Conn).ConnectionState().PeerCertificates
			if peerCerts == nil {
				log.Printf("simpleserver: can't get peer list\n")
			} else {
				peerCert := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
				if peerCert.Raw == nil {
					log.Printf("simpleserver: can't get peer name\n")
				} else {
					if peerCert.Subject.OrganizationalUnit != nil {
						clientName = peerCert.Subject.OrganizationalUnit[0]
					}
				}
			}
			log.Printf("simpleserver, peer name: %s\n", clientName)
			ms := util.NewMessageStream(conn)
			go serviceThead(ms, clientName, serverProgramPolicy)
		}
	}
}

func main() {

	var serverProgramPolicy fileproxy.ProgramPolicy

	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort

	// Load CloudProxy domain configuration.
	simpleDomain, err := tao.LoadDomain(*simplecfg, nil)
	if err != nil {
		log.Fatalln("simpleserver: can't LoadDomain")
	}
	log.Printf("simpleserver: Domain name: %s\n", simpleDomain.ConfigPath)

	// Get policy cert for this domain.
	var derPolicyCert []byte
	if simpleDomain.Keys.Cert != nil {
		derPolicyCert = simpleDomain.Keys.Cert.Raw
	}
	if derPolicyCert == nil {
		log.Fatalln("simpleserver: can't retrieve policy cert")
	}

	err = simpleDomain.ExtendTaoName(tao.Parent())
	if err != nil {
		log.Fatalln("simpleserver: can't extend the Tao with the policy key")
	}

	// Extend my name.
	e := auth.PrinExt{Name: "simpleserver_version_1"}
	err = tao.Parent().ExtendTaoName(auth.SubPrin{e})
	if err != nil {
		return
	}
	taoName, err := tao.Parent().GetTaoName()
	if err != nil {
		log.Printf("simpleserver: cant get tao name\n")
		return
	}
	log.Printf("simpleserver: my name is %s\n", taoName)

	// Get my keys and certs (or initialize them).
	var programCert []byte
	sealedSymmetricKey, sealedSigningKey, programCert, delegation, err := fileproxy.LoadProgramKeys(*simpleserverPath)
	if err != nil {
		log.Printf("simpleserver: cant retrieve key material\n")
	}
	if sealedSymmetricKey == nil || sealedSigningKey == nil || delegation == nil || programCert == nil {
		log.Printf("simpleserver: No key material present\n")
	}

	// Get my symmetric keys.
	var symKeys []byte

	// Make sure my keys are zeroed.
	defer simplecommon.ZeroBytes(symKeys)

	if sealedSymmetricKey != nil {
		symKeys, policy, err := tao.Parent().Unseal(sealedSymmetricKey)
		if err != nil {
			return
		}
		if policy != tao.SealPolicyDefault {
			log.Printf("simpleserver: unexpected policy on unseal\n")
		}
		log.Printf("simpleserver: Unsealed symKeys: % x\n", symKeys)
	} else {
		symKeys, err = simplecommon.InitializeSealedSymmetricKeys(*simpleserverPath,
			tao.Parent(), fileproxy.SizeofSymmetricKeys)
		if err != nil {
			log.Printf("simpleserver: InitializeSealedSymmetricKeys error: %s\n", err)
		}
		log.Printf("simpleserver: InitilizedsymKeys: % x\n", symKeys)
	}

	// Get my Program Key.
	var signingKey *tao.Keys
	if sealedSigningKey != nil {
		log.Printf("retrieving signing key\n")
		signingKey, err = simplecommon.SigningKeyFromBlob(tao.Parent(),
			sealedSigningKey, programCert, delegation)
		if err != nil {
			log.Printf("simpleserver: SigningKeyFromBlob error: %s\n", err)
		}
		log.Printf("simpleserver: Retrieved Signing key: % x\n", *signingKey)
	} else {
		log.Printf("simpleserver: initializing signing key\n")
		signingKey, err = simplecommon.InitializeSealedSigningKey(*simpleserverPath,
			tao.Parent(), *simpleDomain)
		if err != nil {
			log.Printf("simpleserver: InitializeSealedSigningKey error: %s\n", err)
		}
		log.Printf("simpleserver: Initialized signingKey\n")
		programCert = signingKey.Cert.Raw
	}
	taoNameStr := taoName.String()

	_ = serverProgramPolicy.InitProgramPolicy(derPolicyCert, taoNameStr, *signingKey, symKeys, programCert)

	err = server(serverAddr, taoNameStr, derPolicyCert, signingKey, &serverProgramPolicy)
	if err != nil {
		log.Printf("simpleserver: server error\n")
	}
	log.Printf("simpleserver: done\n")
}
