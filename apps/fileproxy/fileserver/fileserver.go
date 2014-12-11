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
// File: fileserver.go

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

func serve(addr, fp string, cert []byte, signingKey *tao.Keys, policy *fileproxy.ProgramPolicy) error {
	m := fileproxy.NewResourceMaster(fp)

	policyCert, err := x509.ParseCertificate(cert)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AddCert(policyCert)
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
	log.Println("fileserver listening")
	sock, err := tls.Listen("tcp", addr, conf)
	if err != nil {
		return err
	}

	for {
		// Accept and handle client connections one at a time.
		conn, err := sock.Accept()
		if err != nil {
			return err
		}

		var clientName string
		if err = conn.(*tls.Conn).Handshake(); err != nil {
			log.Printf("fileserver: couldn't perform handshake: %s\n", err)
			continue
		}

		peerCerts := conn.(*tls.Conn).ConnectionState().PeerCertificates
		if peerCerts == nil {
			log.Println("fileserver: couldn't get peer list")
			continue
		}

		peerCert := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
		if peerCert.Raw == nil {
			log.Println("fileserver: couldn't get peer name")
			continue
		}

		if peerCert.Subject.OrganizationalUnit != nil {
			clientName = peerCert.Subject.OrganizationalUnit[0]
		}
		log.Printf("fileserver: peer name: '%s'\n", clientName)
		ms := util.NewMessageStream(conn)

		// TODO(tmroeder): support multiple simultaneous clients. This
		// requires, e.g., adding locking to the ResourceMaster.
		if err := m.RunMessageLoop(ms, policy); err != nil {
			log.Printf("fileserver: failed to run message loop: %s\n", err)
			continue
		}

		log.Println("Finished handling the client messages")
	}
}

func main() {
	hostcfg := flag.String("hostconfig", "tao.config", "path to host tao configuration")
	serverHost := flag.String("host", "localhost", "address for client/server")
	serverPort := flag.String("port", "8123", "port for client/server")
	fileServerPath := flag.String("fileserver_files", "fileserver_files/", "fileserver directory")
	fileServerFilePath := flag.String("stored_files", "fileserver_files/stored_files/", "fileserver directory")

	flag.Parse()

	serverAddr := net.JoinHostPort(*serverHost, *serverPort)
	hostDomain, err := tao.LoadDomain(*hostcfg, nil)
	if err != nil {
		log.Fatalln("fileserver: can't LoadDomain")
	}

	var policyCert []byte
	if hostDomain.Keys.Cert != nil {
		policyCert = hostDomain.Keys.Cert.Raw
	}
	if policyCert == nil {
		log.Fatalln("fileserver: can't retrieve policy cert")
	}

	if err := hostDomain.ExtendTaoName(tao.Parent()); err != nil {
		log.Fatalln("fileserver: can't extend the Tao with the policy key")
	}
	e := auth.PrinExt{Name: "fileserver_version_1"}
	if err = tao.Parent().ExtendTaoName(auth.SubPrin{e}); err != nil {
		log.Fatalln("fileserver: couldn't extend the Tao name")
	}

	taoName, err := tao.Parent().GetTaoName()
	if err != nil {
		log.Fatalln("fileserver: couldn't get tao name")
	}

	var programCert []byte
	sealedSymmetricKey, sealedSigningKey, programCert, delegation, err := fileproxy.LoadProgramKeys(*fileServerPath)
	if err != nil {
		log.Println("fileserver: couldn't retrieve key material")
	}
	if sealedSymmetricKey == nil || sealedSigningKey == nil || delegation == nil || programCert == nil {
		log.Println("fileserver: no key material present")
	}

	var symKeys []byte
	defer fileproxy.ZeroBytes(symKeys)
	if sealedSymmetricKey != nil {
		var policy string
		if symKeys, policy, err = tao.Parent().Unseal(sealedSymmetricKey); err != nil {
			log.Fatalln("fileserver: couldn't unseal the symmetric key")
		}
		if policy != tao.SealPolicyDefault {
			log.Fatalln("fileserver: unexpected policy on unseal")
		}
	} else {
		symKeys, err = fileproxy.InitializeSealedSymmetricKeys(*fileServerPath, tao.Parent(), fileproxy.SymmetricKeySize)
		if err != nil {
			log.Fatalf("fileserver: InitializeSealedSymmetricKeys error: %s\n", err)
		}
	}

	var signingKey *tao.Keys
	if sealedSigningKey != nil {
		signingKey, err = fileproxy.SigningKeyFromBlob(tao.Parent(),
			sealedSigningKey, programCert, delegation)
		if err != nil {
			log.Fatalf("fileserver: SigningKeyFromBlob error: %s\n", err)
		}
	} else {
		signingKey, err = fileproxy.InitializeSealedSigningKey(*fileServerPath,
			tao.Parent(), *hostDomain)
		if err != nil {
			log.Fatalf("fileserver: InitializeSealedSigningKey error: %s\n", err)
		}
		programCert = signingKey.Cert.Raw
	}

	progPolicy := fileproxy.NewProgramPolicy(policyCert, taoName.String(), signingKey, symKeys, programCert)

	serve(serverAddr, *fileServerFilePath, policyCert, signingKey, progPolicy)
	if err != nil {
		log.Printf("fileserver: server error\n")
	}
	log.Printf("fileserver: done\n")
}
