// Copyright (c) 2014, Google, Inc. All rights reserved.
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
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"path"

	"code.google.com/p/goprotobuf/proto"

	"github.com/jlmucb/cloudproxy/apps/fileproxy"
	"github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
	"github.com/jlmucb/cloudproxy/util"
)

func main() {

	// TODO(tmroeder): remove the relative path.
	hostcfg := flag.String("hostconfig", "../hostdomain/tao.config", "path to host tao configuration")
	serverHost := flag.String("host", "localhost", "address for client/server")
	serverPort := flag.String("port", "8123", "port for client/server")
	rollbackServerHost := flag.String("rollbackhost", "localhost", "address for rollback client/server")
	rollbackServerPort := flag.String("rollbackport", "8129", "port for client/server")
	fileClientPath := flag.String("fileclient_files", "fileclient_files", "fileclient directory")
	fileClientFilePath := flag.String("stored_files", "fileclient_files/stored_files", "fileclient file directory")
	testFile := flag.String("test_file", "originalTestFile", "test file")
	fileClientKeyPath := flag.String("usercreds", "usercreds", "user keys and certs")

	flag.Parse()

	serverAddr := net.JoinHostPort(*serverHost, *serverPort)
	hostDomain, err := tao.LoadDomain(*hostcfg, nil)
	if err != nil {
		log.Fatalln("fileclient: Can't load domain")
	}
	var derPolicyCert []byte
	if hostDomain.Keys.Cert != nil {
		derPolicyCert = hostDomain.Keys.Cert.Raw
	}
	if derPolicyCert == nil {
		log.Fatalln("fileclient: Can't retrieve policy cert")
	}

	if err := hostDomain.ExtendTaoName(tao.Parent()); err != nil {
		log.Fatalln("fileclient: can't extend the Tao with the policy key")
	}
	e := auth.PrinExt{Name: "fileclient_version_1"}
	err = tao.Parent().ExtendTaoName(auth.SubPrin{e})
	if err != nil {
		return
	}

	taoName, err := tao.Parent().GetTaoName()
	if err != nil {
		log.Fatalln("fileclient: Can't get tao name")
		return
	}

	// Load the keys from disk or create a new set of keys and write them to
	// disk.
	// TODO(tmroeder): this should be refactored.
	sealedSymmetricKey, sealedSigningKey, programCert, delegation, err := fileproxy.LoadProgramKeys(*fileClientPath)
	if err != nil {
		log.Printf("fileclient: can't retrieve key material\n")
	}
	if sealedSymmetricKey == nil || sealedSigningKey == nil || delegation == nil || programCert == nil {
		log.Printf("fileclient: No key material present\n")
	}

	var symKeys []byte
	if sealedSymmetricKey != nil {
		var policy string
		symKeys, policy, err = tao.Parent().Unseal(sealedSymmetricKey)
		if err != nil {
			return
		}
		if policy != tao.SealPolicyDefault {
			log.Fatalln("fileclient: unexpected policy on unseal")
		}
	} else {
		symKeys, err = fileproxy.InitializeSealedSymmetricKeys(*fileClientPath, tao.Parent(), fileproxy.SymmetricKeySize)
		if err != nil {
			log.Fatalln("fileclient: InitializeSealedSymmetricKeys error: %s", err)
		}
	}
	defer fileproxy.ZeroBytes(symKeys)

	var signingKey *tao.Keys
	if sealedSigningKey != nil {
		signingKey, err = fileproxy.SigningKeyFromBlob(tao.Parent(), sealedSigningKey, programCert, delegation)
		if err != nil {
			log.Fatalln("fileclient: SigningKeyFromBlob error: %s", err)
		}
	} else {
		signingKey, err = fileproxy.InitializeSealedSigningKey(*fileClientPath, tao.Parent(), *hostDomain)
		if err != nil {
			log.Fatalln("fileclient: InitializeSealedSigningKey error: %s", err)
		}
	}

	// Get the policy cert and set up TLS.
	policyCert, err := x509.ParseCertificate(derPolicyCert)
	if err != nil {
		log.Fatalln("fileclient:can't ParseCertificate")
	}
	pool := x509.NewCertPool()
	pool.AddCert(policyCert)

	tlsc, err := taonet.EncodeTLSCert(signingKey)
	if err != nil {
		log.Fatalln("fileclient, encode error: ", err)
	}
	conn, err := tls.Dial("tcp", serverAddr, &tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: false,
	})
	if err != nil {
		log.Fatalln("fileclient: can't establish channel: ", err)
	}
	ms := util.NewMessageStream(conn)

	// Authenticate user principal(s).
	keyDir := path.Join(*fileClientPath, *fileClientKeyPath)

	// Get the cert.
	certPath := path.Join(keyDir, "cert")
	userCert, err := ioutil.ReadFile(certPath)
	if err != nil {
		log.Fatalln("fileclient: can't read cert from ", certPath)
	}

	// Get the keys.
	keyPath := path.Join(keyDir, "keys")
	pks, err := ioutil.ReadFile(keyPath)
	if err != nil {
		log.Fatalln("fileclient: can't read key blob")
	}
	var cks tao.CryptoKeyset
	err = proto.Unmarshal(pks, &cks)
	if err != nil {
		log.Fatalln("fileclient: can't proto unmarshal key set")
	}
	userKey, err := tao.UnmarshalKeyset(&cks)
	if err != nil {
		log.Fatalln("fileclient: can't unmarshal key set")
	}

	// Authenticate a key to use for requests to the server.
	if err = fileproxy.AuthenticatePrincipal(ms, userKey, userCert); err != nil {
		log.Fatalf("fileclient: can't authenticate principal: %s", err)
	}

	// Create a file.
	sentFileName := *testFile
	if err = fileproxy.CreateFile(ms, userCert, sentFileName); err != nil {
		log.Fatalln("fileclient: can't create file")
	}

	// Send File.
	if err = fileproxy.WriteFile(ms, userCert, *fileClientFilePath, sentFileName); err != nil {
		log.Fatalf("fileclient: couldn't write the file %s to the server: %s", sentFileName, err)
	}

	// Get file.
	outputFileName := sentFileName + ".out"
	if err = fileproxy.ReadFile(ms, userCert, *fileClientFilePath, sentFileName, outputFileName); err != nil {
		log.Fatalf("fileclient: couldn't get file %s to output file %s: %s", sentFileName, outputFileName, err)
	}

	// TODO(tmroeder): compare the received file against the sent file.

	// Set up a TLS connection to the rollback server, just like the one to
	// the file server.
	rollbackServerAddr := net.JoinHostPort(*rollbackServerHost, *rollbackServerPort)
	rbconn, err := tls.Dial("tcp", rollbackServerAddr, &tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: false,
	})
	if err != nil {
		log.Fatalf("fileclient: can't establish rollback channel: %s", err)
	}
	newms := util.NewMessageStream(rbconn)

	// Create a fake hash value, and set this value for an item.
	hashLen := 32
	hash := make([]byte, hashLen)
	if _, err := rand.Read(hash); err != nil {
		log.Fatalf("fileclient: failed to read a random value for the hash")
	}

	progName := taoName.String()
	resName := "test_resource"
	if err := fileproxy.SetHash(newms, resName, hash); err != nil {
		log.Fatalf("Couldn't set the hash for program '%s', resource '%s', hash % x on the remote server: %s", progName, resName, hash, err)
	}

	// Set the counter to 10 and check that we get the same value back.
	if err := fileproxy.SetCounter(newms, uint64(10)); err != nil {
		log.Fatalf("fileclient: couldn't set the counter in the file client")
	}

	c, err := fileproxy.GetCounter(newms)
	if err != nil {
		log.Fatalf("fileclient: couldn't get the value of the counter from the rollback server")
	}

	// Get the hash verification value.
	newHash, err := fileproxy.GetHashedVerifier(newms, resName)
	if err != nil {
		log.Fatalf("fileclient: couldn't get the hashed verifier from the rollback server")
	}

	// Try to recompute the hashed verifier directly to see if it matches.
	sh := sha256.New()
	vi := fileproxy.EncodeCounter(c)
	sh.Write(vi)
	sh.Write(hash)
	sh.Write(vi)
	computed := sh.Sum(nil)
	if subtle.ConstantTimeCompare(newHash, computed) != 1 {
		log.Fatalf("fileclient: the hashed verifier % x returned by the server didn't match the value % x computed locally", newHash, computed)
	}

	log.Println("All fileclient tests pass")
}
