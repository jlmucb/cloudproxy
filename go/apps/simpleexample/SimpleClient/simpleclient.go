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
// File: simpleclient.go

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"

	"github.com/jlmucb/cloudproxy/go/apps/simpleexample/common"
	taosupport "github.com/jlmucb/cloudproxy/go/support_libraries/tao_support"
	"github.com/jlmucb/cloudproxy/go/tao"
)

var caAddr = flag.String("caAddr", "localhost:8124", "The address to listen on")
var simpleCfg = flag.String("domain_config",
	"./tao.config",
	"path to tao configuration")
var simpleClientPath = flag.String("path",
	"./SimpleClient",
	"path to SimpleClient files")
var testRollback = flag.Bool("test_rollback", false, "test rollback?")
var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var useSimpleDomainService = flag.Bool("use_simpledomainservice", true,
	"whether to use simple domain service")
var serverAddr string

func main() {

	// This holds the cloudproxy specific data for simpleclient
	// including the Program Cert and Program Private key.
	var clientProgramData taosupport.TaoProgramData

	// Make sure we zero keys when we're done.
	defer clientProgramData.ClearTaoProgramData()

	// Parse flags
	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort

	// If TaoParadigm completes without error, clientProgramData contains all the
	// Cloudproxy information needed throughout simpleclient execution.
	err := taosupport.TaoParadigm(simpleCfg, simpleClientPath, "ECC-P-256.aes128.hmacaes256",
		*useSimpleDomainService, *caAddr, &clientProgramData)
	if err != nil {
		log.Fatalln("simpleclient: Can't establish Tao: ", err)
	}
	fmt.Printf("simpleclient: TaoParadigm complete, name: %s\n",
		clientProgramData.TaoName)

	if *testRollback {
		err = tao.Parent().InitCounter("label", 0)
		if err != nil {
			fmt.Printf("simpleClient: Error return from InitCounter %s\n", err)
		} else {
			fmt.Printf("simpleClient: InitCounter, no error\n")
		}
		c, err := tao.Parent().GetCounter("label")
		if err != nil {
			fmt.Printf("simpleClient: Error Return from GetCounter %d %s\n", c, err)
		} else {
			fmt.Printf("simpleclient: GetCounter successful %d\n", c)
		}
		data := []byte{
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5,
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5}
		sealed, err := tao.Parent().RollbackProtectedSeal("label", data,
			tao.SealPolicyDefault) // REMOVE
		if err != nil {
			fmt.Printf("simpleClient: Error Return from RollbackProtectedSeal %s\n", err)
		} else {
			fmt.Printf("simpleClient: RollbackProtectedSeal successful %x\n", sealed)
		}
		c, err = tao.Parent().GetCounter("label")
		if err != nil {
			fmt.Printf("simpleClient: Error Return from GetCounter %d %s\n", c, err)
		} else {
			fmt.Printf("simpleclient: GetCounter successful %d\n", c)
		}
		recoveredData, _, err := tao.Parent().RollbackProtectedUnseal(sealed)
		if err != nil {
			fmt.Printf("simpleClient: Error Return from RollbackProtectedUnseal %s\n", err)
		} else {
			fmt.Printf("simpleClient: RollbackProtectedUnseal successful %x\n", recoveredData)
		}
		fmt.Printf("data: %x, recovered data: %x\n", data, recoveredData)
	}

	// Open the Tao Channel using the Program key. This program does all the
	// standard channel negotiation and presents the secure server name
	// after negotiation is complete.
	ms, serverName, err := taosupport.OpenTaoChannel(&clientProgramData,
		&serverAddr)
	if err != nil {
		log.Fatalln("simpleclient: Can't establish Tao Channel")
	}
	log.Printf("simpleclient: establish Tao Channel with %s, %s\n",
		serverAddr, serverName)

	// Send a simple request and get response.
	// We have a simple service protobuf for requests and reponsed between
	// simpleclient and simpleserver.  There's only on request: tell me the
	// secret.
	secretRequest := "SecretRequest"

	msg := new(simpleexample_messages.SimpleMessage)
	msg.RequestType = &secretRequest
	simpleexample_messages.SendRequest(ms, msg)
	if err != nil {
		log.Fatalln("simpleclient: Error in response to SendRequest\n")
	}
	respmsg, err := simpleexample_messages.GetResponse(ms)
	if err != nil {
		log.Fatalln("simpleclient: Error in response to GetResponse\n")
	}

	// This is the secret.
	retrieveSecret := respmsg.Data[0]

	// Encrypt and store the secret in simpleclient's save area.
	out, err := taosupport.Protect(clientProgramData.ProgramSymKeys, retrieveSecret)
	if err != nil {
		log.Fatalln("simpleclient: Error protecting data\n")
	}
	err = ioutil.WriteFile(path.Join(*simpleClientPath,
		"retrieved_secret"), out, os.ModePerm)
	if err != nil {
		log.Fatalln("simpleclient: error saving retrieved secret\n")
	}

	// Close down.
	log.Printf("simpleclient: secret is %s, done\n", retrieveSecret)
}
