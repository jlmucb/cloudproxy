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
	"log"
	"net"
	"os"
	"path"

	"github.com/jlmucb/cloudproxy/apps/fileproxy"
	"github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
	"github.com/jlmucb/cloudproxy/util"
)

func main() {

	caAddr := flag.String("caAddr", "localhost:8124", "The address of the CA for setting up a certificate signed by the policy key")
	hostcfg := flag.String("hostconfig", "tao.config", "path to host tao configuration")
	serverHost := flag.String("host", "localhost", "address for client/server")
	serverPort := flag.String("port", "8123", "port for client/server")
	rollbackServerHost := flag.String("rollbackhost", "localhost", "address for rollback client/server")
	rollbackServerPort := flag.String("rollbackport", "8129", "port for client/server")
	fileClientPassword := flag.String("password", "BogusPass", "A password for unlocking the user certificates")
	fileClientPath := flag.String("fileclient_files", "fileclient_files", "fileclient directory")
	fileClientFilePath := flag.String("stored_files", "fileclient_files/stored_files", "fileclient file directory")
	testFile := flag.String("test_file", "originalTestFile", "test file")
	fileClientKeyPath := flag.String("usercreds", "usercreds", "user keys and certs")
	country := flag.String("country", "US", "The country for the fileclient certificate")
	org := flag.String("organization", "Google", "The organization for the fileclient certificate")

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

	parentTao := tao.Parent()
	if err := hostDomain.ExtendTaoName(parentTao); err != nil {
		log.Fatalln("fileclient: can't extend the Tao with the policy key")
	}
	e := auth.PrinExt{Name: "fileclient_version_1"}
	if err = parentTao.ExtendTaoName(auth.SubPrin{e}); err != nil {
		log.Fatalln("fileclient: couldn't extend the tao name with the policy key")
	}

	taoName, err := parentTao.GetTaoName()
	if err != nil {
		log.Fatalln("fileclient: Can't get tao name")
	}

	// Create or read the keys for fileclient.
	fcKeys, err := tao.NewOnDiskTaoSealedKeys(tao.Signing|tao.Crypting, parentTao, *fileClientPath, tao.SealPolicyDefault)
	if err != nil {
		log.Fatalln("fileclient: couldn't set up the Tao-sealed keys:", err)
	}

	// Set up a temporary cert for communication with keyNegoServer.
	fcKeys.Cert, err = fcKeys.SigningKey.CreateSelfSignedX509(tao.NewX509Name(tao.X509Details{
		Country:      *country,
		Organization: *org,
		CommonName:   taoName.String(),
	}))
	if err != nil {
		log.Fatalln("fileclient: couldn't create a self-signed cert for fileclient keys:", err)
	}

	// Contact keyNegoServer for the certificate.
	if err := fileproxy.EstablishCert("tcp", *caAddr, fcKeys, hostDomain.Keys.VerifyingKey); err != nil {
		log.Fatalf("fileclient: couldn't establish a cert signed by the policy key: %s", err)
	}

	// Get the policy cert and set up TLS.
	pool := x509.NewCertPool()
	pool.AddCert(hostDomain.Keys.Cert)

	tlsc, err := taonet.EncodeTLSCert(fcKeys)
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
	if _, err := os.Stat(keyDir); err != nil {
		log.Fatalf("fileclient: couldn't get user credentials from %s: %s\n", keyDir, err)
	}

	// This method won't generate the right certificate in general for
	// signing, which is why we check first to make sure the right directory
	// already exists. But it will successfully read the signer and the
	// certificate.
	userKeys, err := tao.NewOnDiskPBEKeys(tao.Signing, []byte(*fileClientPassword), keyDir, nil)
	if err != nil {
		log.Fatalf("Couldn't read the keys from %s: %s\n", keyDir, err)
	}
	userCert := userKeys.Cert.Raw

	// Authenticate a key to use for requests to the server.
	if err = fileproxy.AuthenticatePrincipal(ms, userKeys, userCert); err != nil {
		log.Fatalf("fileclient: can't authenticate principal: %s", err)
	}

	// Create a file.
	sentFileName := *testFile
	if err = fileproxy.CreateFile(ms, userCert, sentFileName); err != nil {
		log.Fatalln("fileclient: can't create file:", err)
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
