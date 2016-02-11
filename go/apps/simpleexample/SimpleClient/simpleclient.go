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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"io/ioutil"
	"log"

	"code.google.com/p/goprotobuf/proto"

	"github.com/jlmucb/cloudproxy/apps/simplecommon"
	tao "github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
	"github.com/jlmucb/cloudproxy/util"
)

var simplecfg = flag.String("../simpledomain/tao.config", "../simpledomain/tao.config",
			"path to tao configuration")
var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var serverAddr string

func main() {

	// This holds the cloudproxy specific data for this program
	// like Program Cert and Program Private key.
	var clientProgramData simpleexample.TaoProgramData

	// Parse flags
	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort

	// Load domain info for this domain
	// This was initialized by TODO.
	if !TaoParadigm(*simplecfg, &clientProgramData) {
		log.Fatalln("simpleclient: Can't establish Tao")
	}

	// Open the Tao Channel using the Program key.
	ms, serverName, err := OpenTaoChannel(&clientProgramData)
	if err != nil {
		log.Fatalln("simpleclient: Can't establish Tao Channel")
	}
	log.Printf("Establish Tao Channel with %s\n", serverName)

	// Send a simple request and get response.
	var retrievedSecret string
	/*
	rule := "Delegate(\"jlm\", \"tom\", \"getfile\",\"myfile\")"
	log.Printf("simpleclient, sending rule: %s\n", rule)
	err = simplecommon.SendRule(ms, rule, userCert)
	if err != nil {
		log.Printf("simpleclient: can't create file\n")
		return
	}
	status, message, size, err := simplecommon.GetResponse(ms)
	if err != nil {
		log.Fatalln("simpleclient: Error in response to SendCreate\n")
	}
	simplecommon.PrintResponse(status, message, size)
	if *status != "succeeded" {
		return
	}
	*/

	// Close down
	log.Printf("simpleclient: secret is %s, done\n")
}
