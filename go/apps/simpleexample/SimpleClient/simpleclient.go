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

	taosupport "github.com/jlmucb/cloudproxy/go/apps/simpleexample/taosupport"
)

var simpleCfg = flag.String("tao.config",
			"/Domains/domain.simpleexample/tao.config",
			"path to tao configuration")
var simpleClientPath = flag.String("/Domains/domain.simpleexample/SimpleClient", 
			"/Domains/domain.simpleexample/SimpleClient",
			"path to SimpleClient files")
var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var serverAddr string

func main() {

	// This holds the cloudproxy specific data for simpleclient
	// including the Program Cert and Program Private key.
	var clientProgramData taosupport.TaoProgramData

	// Make sure we zero keys when we're done.
	defer taosupport.ClearTaoProgramData(&clientProgramData)

	// Parse flags
	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort

	// If TaoParadigm completes without error, clientProgramData contains all the
	// Cloudproxy information needed throughout simpleclient execution.
	if taosupport.TaoParadigm(simpleCfg, simpleClientPath, &clientProgramData) !=
			nil {
		log.Fatalln("simpleclient: Can't establish Tao")
	}
	fmt.Printf("simpleclient: TaoParadigm complete, name: %s\n",
	   clientProgramData.TaoName)

	// Open the Tao Channel using the Program key.  This program does all the
	// standard channel negotiation and presents the secure server name after
	// negotiation is complete.
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

	msg := new(taosupport.SimpleMessage)
	msg.RequestType = &secretRequest
	taosupport.SendRequest(ms, msg)
	if err != nil {
		log.Fatalln("simpleclient: Error in response to SendRequest\n")
	}
	respmsg, err := taosupport.GetResponse(ms)
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
