// Copyright (c) 2016, Google, Inc.,  All rights reserved.
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
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"path"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/taotataoo"
	taosupport "github.com/jlmucb/cloudproxy/go/support_libraries/tao_support"

	"github.com/jlmucb/cloudproxy/go/apps/newfileproxy/common"
	"github.com/jlmucb/cloudproxy/go/apps/newfileproxy/resourcemanager"
)

var caAddr = flag.String("caAddr", "localhost:8124", "The address to listen on")
var simpleCfg = flag.String("domain_config",
	"./tao.config",
	"path to tao configuration")
var fileClientPath = flag.String("path",
	"./FileClient",
	"path to FileClient files")
var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var useSimpleDomainService = flag.Bool("use_simpledomainservice", true,
	"whether to use simple domain service")
var serverAddr string

func main() {

	// This holds the cloudproxy specific data for fileclient
	// including the Program Cert and Program Private key.
	var clientProgramData taosupport.TaoProgramData

	// Make sure we zero keys when we're done.
	defer clientProgramData.ClearTaoProgramData()

	// Parse flags
	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort

	// If TaoParadigm completes without error, clientProgramData contains all the
	// Cloudproxy information needed throughout fileclient execution.
	err := taosupport.TaoParadigm(simpleCfg, fileClientPath, "ECC-P-256.aes128.hmacaes256",
		*useSimpleDomainService, *caAddr, &clientProgramData)
	if err != nil {
		fmt.Printf("fileclient: Can't establish Tao: ", err)
	}
	fmt.Printf("newfileclient: TaoParadigm complete, name: %s\n",
		clientProgramData.TaoName)

	// Fill Client data
	clientData := new(common.ClientData)
	if clientData == nil {
		fmt.Printf("fileclient: bad clientData init ")
		return
	}
	certificate, err := x509.ParseCertificate(clientProgramData.PolicyCert)
	if err != nil {
		fmt.Printf("fileclient: bad ParseCertificate: ", err)
		return
	}
	clientData.PolicyCert = certificate
	// initialize user keys

	// Get File Secrets
	secretsFileName := path.Join(*fileClientPath, "FileSecrets.bin")

	// fileSecrets is used to encrypt/decrypt client files.
	fileSecrets := make([]byte, 32)

	encryptedFileSecrets, err := ioutil.ReadFile(secretsFileName)
	if err != nil {
		rand.Read(fileSecrets)
	} else {
		fileSecrets, err = tao.Unprotect(clientProgramData.ProgramSymKeys, encryptedFileSecrets)
		if err != nil {
			fmt.Printf("fileclient: Error protecting data\n")
		}
	}

	// Get User Certificates and Private keys
	userKeysFileName := path.Join(*fileClientPath, "serialized_user_keys")
	userKeyFile, err := ioutil.ReadFile(userKeysFileName)
	if err != nil {
		fmt.Printf("fileclient: bad user certs: ", err)
		return
	}
	userKeys := new(common.UserKeysMessage)
	err = proto.Unmarshal(userKeyFile, userKeys)
	if err != nil {
		fmt.Printf("fileclient: bad user certs unmarshal: ", err)
		return
	}

	// Deserialize keys.
	var UserKeyArray []common.KeyData
	for i := 0; i < len(userKeys.SerializedKeys); i++ {
		userKey, err := common.ParseUserKey(userKeys.SerializedKeys[i])
		if err != nil {
		}
		certificate, err := x509.ParseCertificate(userKey.Cert)
		if err != nil {
		}
		userKey.Certificate = certificate
		UserKeyArray = append(UserKeyArray, *userKey)
	}

	// Open the Tao Channel using the Program key. This program does all the
	// standard channel negotiation and presents the secure server name
	// after negotiation is complete.
	ms, serverName, err := taosupport.OpenTaoChannel(&clientProgramData, &serverAddr)
	if err != nil {
		fmt.Printf("fileclient: Can't establish Tao Channel")
		return
	}
	fmt.Printf("fileclient: established Tao Channel with %s, %s\n",
		serverAddr, serverName)

	// Authenticate Principals
	for i := 0; i < len(UserKeyArray); i++ {
		err = common.RequestChallenge(ms, UserKeyArray[i])
		if err != nil {
			fmt.Printf("fileclient: common.RequestChallenge %d fails\n", i)
			return
		}
	}
	fmt.Printf("All common.RequestChallenge's succeeded\n")

	// Create a directory.
	err = common.Create(ms, "directory1", resourcemanager.ResourceType_DIRECTORY, UserKeyArray[0].Cert)
	if err != nil {
		fmt.Printf("fileclient: common.Create 1 fails\n")
		return
	}

	// Create a file.
	err = common.Create(ms, "directory1/file1", resourcemanager.ResourceType_FILE, UserKeyArray[0].Cert)
	if err != nil {
		fmt.Printf("fileclient: common.Create 2 fails\n")
		return
	}
	fmt.Printf("Creates succeeded\n")

	// Add a few owners, readers, writers
	var newcerts [][]byte
	newcerts = append(newcerts, UserKeyArray[1].Cert)
	err = common.AddOwner(ms, "directory1/file1", newcerts)
	if err != nil {
		fmt.Printf("fileclient: common.AddOwner fails\n")
		return
	}
	fmt.Printf("AddOwner succeeded\n")

	newcerts = append(newcerts, UserKeyArray[2].Cert)
	err = common.AddReader(ms, "directory1/file1", newcerts)
	if err != nil {
		fmt.Printf("fileclient: common.AddReader fails\n")
		return
	}
	fmt.Printf("AddReader succeeded\n")

	err = common.AddWriter(ms, "directory1/file1", newcerts)
	if err != nil {
		fmt.Printf("fileclient: common.AddWriter fails\n")
		return
	}
	fmt.Printf("AddWriter succeeded\n")

	// Write a resource.
	file1Contents := []byte{1, 2, 3}
	err = common.WriteResource(ms, "directory1/file1", file1Contents)
	if err != nil {
		fmt.Printf("fileclient: common.WriteResource fails\n")
		return
	}
	fmt.Printf("common.WriteResource succeeded\n")

	// Read a resource.
	recoverdFile1Contents, err := common.ReadResource(ms, "directory1/file1")
	if err != nil {
		fmt.Printf("fileclient: common.ReadResource fails\n")
		return
	}
	if bytes.Compare(file1Contents, recoverdFile1Contents) != 0 {
		fmt.Printf("fileclient: written file differs from read file\n")
	}
	fmt.Printf("common.ReadResource succeeded\n")

	// Tell Server to save state
	err = common.SaveState(ms)
	if err == nil {
		fmt.Printf("common.SaveState succeeded\n")
	} else {
		fmt.Printf("common.SaveState failed\n")
	}

	// Encrypt and store the secret in fileclient's save area.
	encryptedFileSecrets, err = tao.Protect(clientProgramData.ProgramSymKeys, fileSecrets)
	if err != nil {
		fmt.Printf("fileclient: Error protecting data\n")
	}
	err = ioutil.WriteFile(secretsFileName, encryptedFileSecrets, 0666)
	if err != nil {
		fmt.Printf("fileclient: error saving retrieved secret\n")
	}
	fmt.Printf("Secrets and table saved\n")

	// Close down.
	fmt.Printf("fileclient completes with no errors\n")
}
