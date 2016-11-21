// Copyright (c) 2014, Google, Inc.,  All rights reserved.
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
// File: fileclient.go

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"

	"github.com/jlmucb/cloudproxy/go/tao"
	taosupport "github.com/jlmucb/cloudproxy/go/apps/simpleexample/taosupport"

	"github.com/jlmucb/cloudproxy/go/apps/newfileproxy/common"
)

var simpleCfg = flag.String("domain_config",
	"./tao.config",
	"path to tao configuration")
var fileClientPath = flag.String("path",
	"./FileClient",
	"path to FileClient files")
var testRollback= flag.Bool("test_rollback", false, "test rollback?")
var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var serverAddr string

func main() {

	// This holds the cloudproxy specific data for fileclient
	// including the Program Cert and Program Private key.
	var clientProgramData taosupport.TaoProgramData

	// Make sure we zero keys when we're done.
	defer taosupport.ClearTaoProgramData(&clientProgramData)

	// Parse flags
	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort

	// If TaoParadigm completes without error, clientProgramData contains all the
	// Cloudproxy information needed throughout fileclient execution.
	err := taosupport.TaoParadigm(simpleCfg, fileClientPath, &clientProgramData)
	if err != nil {
		log.Fatalln("fileclient: Can't establish Tao: ", err)
	}
	fmt.Printf("fileclient: TaoParadigm complete, name: %s\n",
		clientProgramData.TaoName)

	// Fill Client data
	clientData := new(common.ClientData)
	if clientData == nil {
	}
	certificate, err := x509.ParseCertificate(clientProgramData.PolicyCert)
	if err != nil {
	}
	clientData.PolicyCert = &certificate
	// initialize user keys

	// Get File Secrets
	var fileSecrets []byte
	encryptedFileSecrets, err = ioutil.ReadFile(path.Join(*fileClientPath, "FileSecrets.bin")
	if err != nil {
		rand.Read(fileSecrets[0:32])
	} else {
		fileSecrets, err := taosupport.Unprotect(clientProgramData.ProgramSymKeys, encryptedFileSecrets)
		if err != nil {
		log.Fatalln("fileclient: Error protecting data\n")
		}
	}
	if fileSecrets == nil {
	}

	// Get User Certificates and Private keys


	// Open the Tao Channel using the Program key. This program does all the
	// standard channel negotiation and presents the secure server name
	// after negotiation is complete.
	ms, serverName, err := taosupport.OpenTaoChannel(&clientProgramData,
		&serverAddr)
	if err != nil {
		log.Fatalln("fileclient: Can't establish Tao Channel")
	}
	log.Printf("fileclient: establish Tao Channel with %s, %s\n",
		serverAddr, serverName)

	// Authenticate Principals
	// common.RequestChallenge(ms *util.MessageStream, key KeyData)

	// Create a resource.
	// common.Create(ms *util.MessageStream, name string, cert []byte)

	// Add a few owners, readers, writers
	// common.
	// common.AddOwner(ms *util.MessageStream, resourceName string, certs [][]byte) error

	// Write a resource.
	// common.WriteResource(ms *util.MessageStream, resourceName string, fileContents []byte) error

	// Read a resource.
	// common.ReadResource(ms *util.MessageStream, resourceName string) ([]byte, error)

	// Encrypt files and store keys

	// Encrypt and store the secret in fileclient's save area.
	out, err := taosupport.Protect(clientProgramData.ProgramSymKeys, fileSecrets)
	if err != nil {
		log.Fatalln("fileclient: Error protecting data\n")
	}
	err = ioutil.WriteFile(path.Join(*fileClientPath, "FileSecrets.bin", out, 0666)
	if err != nil {
		log.Fatalln("fileclient: error saving retrieved secret\n")
	}

	// Close down.
}
