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
	"github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
	"github.com/jlmucb/cloudproxy/util"
)

func serve(serverAddr string, prin string, policyCert []byte, signingKey *tao.Keys, policy *fileproxy.ProgramPolicy, m *fileproxy.RollbackMaster) error {
	pc, err := x509.ParseCertificate(policyCert)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AddCert(pc)
	tlsc, err := taonet.EncodeTLSCert(signingKey)
	if err != nil {
		return err
	}
	conf := &tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: false,
		ClientAuth:         tls.RequireAnyClientCert,
	}
	log.Println("Rollback server listening")
	sock, err := tls.Listen("tcp", serverAddr, conf)
	if err != nil {
		return err
	}

	for {
		conn, err := sock.Accept()
		if err != nil {
			return err
		}
		var clientName string
		if err = conn.(*tls.Conn).Handshake(); err != nil {
			log.Println("TLS handshake failed")
			continue
		}

		peerCerts := conn.(*tls.Conn).ConnectionState().PeerCertificates
		if peerCerts == nil {
			log.Println("rollbackserver: can't get peer list")
			continue
		}

		peerCert := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
		if peerCert.Raw == nil {
			log.Println("rollbackserver: can't get peer name")
			continue
		}

		if peerCert.Subject.OrganizationalUnit == nil {
			log.Println("No OrganizationalUnit name in the peer certificate. Refusing the connection")
			continue
		}

		clientName = peerCert.Subject.OrganizationalUnit[0]
		ms := util.NewMessageStream(conn)
		// TODO(tmroeder): support multiple simultaneous clients.
		// Add this program as a rollback program.
		log.Printf("Adding a program with name '%s'\n", clientName)
		_ = m.AddRollbackProgram(clientName)
		if err := m.RunMessageLoop(ms, policy, clientName); err != nil {
			log.Printf("rollbackserver: failed to run message loop: %s\n", err)
		}
	}
}

func main() {
	hostcfg := flag.String("hostconfig", "../hostdomain/tao.config", "path to host tao configuration")
	serverHost := flag.String("host", "localhost", "address for client/server")
	serverPort := flag.String("port", "8129", "port for client/server")
	rollbackserverPath := flag.String("rollbackserver_files", "rollbackserver_files/", "rollbackserver directory")

	flag.Parse()
	serverAddr := net.JoinHostPort(*serverHost, *serverPort)

	hostDomain, err := tao.LoadDomain(*hostcfg, nil)
	if err != nil {
		log.Fatalln("rollbackserver: can't load domain")
	}
	var policyCert []byte
	if hostDomain.Keys.Cert != nil {
		policyCert = hostDomain.Keys.Cert.Raw
	}
	if policyCert == nil {
		log.Fatalln("rollbackserver: can't retrieve policy cert")
	}

	if err := hostDomain.ExtendTaoName(tao.Parent()); err != nil {
		log.Fatalln("fileserver: can't extend the Tao with the policy key")
	}
	e := auth.PrinExt{Name: "rollbackserver_version_1"}
	if err = tao.Parent().ExtendTaoName(auth.SubPrin{e}); err != nil {
		log.Fatalln("rollbackserver: can't extend name")
	}

	taoName, err := tao.Parent().GetTaoName()
	if err != nil {
		return
	}

	sealedSymmetricKey, sealedSigningKey, programCert, delegation, err := fileproxy.LoadProgramKeys(*rollbackserverPath)
	if err != nil {
		log.Println("rollbackserver: can't retrieve key material")
	}
	if sealedSymmetricKey == nil || sealedSigningKey == nil || delegation == nil || programCert == nil {
		log.Println("rollbackserver: No key material present")
	}

	var symKeys []byte
	defer fileproxy.ZeroBytes(symKeys)
	if sealedSymmetricKey != nil {
		var policy string
		if symKeys, policy, err = tao.Parent().Unseal(sealedSymmetricKey); err != nil {
			log.Fatalln("rollbackserver: couldn't unseal the symmetric key")
		}
		if policy != tao.SealPolicyDefault {
			log.Fatalln("rollbackserver: unexpected policy on unseal")
		}
	} else {
		if symKeys, err = fileproxy.InitializeSealedSymmetricKeys(*rollbackserverPath, tao.Parent(), fileproxy.SymmetricKeySize); err != nil {
			log.Fatalf("rollbackserver: InitializeSealedSymmetricKeys error: %s\n", err)
		}
	}

	var signingKey *tao.Keys
	if sealedSigningKey != nil {
		if signingKey, err = fileproxy.SigningKeyFromBlob(tao.Parent(), sealedSigningKey, programCert, delegation); err != nil {
			log.Fatalf("rollbackserver: SigningKeyFromBlob error: %s\n", err)
		}
	} else {
		if signingKey, err = fileproxy.InitializeSealedSigningKey(*rollbackserverPath, tao.Parent(), *hostDomain); err != nil {
			log.Fatalf("rollbackserver: InitializeSealedSigningKey error: %s\n", err)
		}
		programCert = signingKey.Cert.Raw
	}

	progPolicy := fileproxy.NewProgramPolicy(policyCert, taoName.String(), signingKey, symKeys, programCert)
	m := fileproxy.NewRollbackMaster(taoName.String())

	if err := serve(serverAddr, taoName.String(), policyCert, signingKey, progPolicy, m); err != nil {
		log.Fatalf("rollbackserver: server error: %s\n", err)
	}
	log.Println("rollbackserver: done")
}
