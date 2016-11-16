// Copyright (c) 2016, Google, Inc.  All rights reserved.
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

// This is a simple example of a server that uses Tao.
// It still uses domains..

package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"

	"github.com/jlmucb/cloudproxy/go/tao"
)

var (
	cfg        = flag.String("domain_config", "./tao.config", "path to simple tao configuration")
	serverPath = flag.String("path", "./simpleserver", "path to Server files")
	secretName = flag.String("secret", "secret", "file name of the secret")
	serverHost = flag.String("host", "localhost", "address for client/server")
	serverPort = flag.String("port", "8123", "port for client/server")
	serverAddr string
)

// Basic Tao Server. For this example, we assume all connections are *not*
// Tao connections (i.e., not TLS), so we don't have any certs or secret key
// To adapt this code to use TLS with certs and keys, look at how taosupport.go
// and simpleserver.go in simpleexample does this.
type TaoServer struct {
	// Program name.
	TaoName string

	// A secret value stored in the server.
	Secret []byte

	// Path for program to read and write files.
	ProgramFilePath *string

	listener net.Listener
}

func NewTaoServer() *TaoServer {

	// Load domain info for this domain.
	domain, err := tao.LoadDomain(*cfg, nil)
	if err != nil {
		log.Fatal("Could not load domain:", err)
	}

	// Extend tao name with policy key
	err = domain.ExtendTaoName(tao.Parent())
	if err != nil {
		log.Fatal("Could not extend name:", err)
	}

	// Retrieve extended name.
	taoName, err := tao.Parent().GetTaoName()
	if err != nil {
		log.Fatal("Could not get extended name:", err)
	}

	var secret []byte
	if _, err = os.Stat(path.Join(*serverPath, *secretName)); os.IsNotExist(err) {
		// Secret has not been created yet. Create one
		secret, err = tao.Parent().GetRandomBytes(64)
		if err != nil {
			log.Fatal("Could not generate secret:", err)
		}
		sealed, err := tao.Parent().Seal(secret, tao.SealPolicyDefault)
		if err != nil {
			log.Fatal("Could not seal secret:", err)
		}
		err = ioutil.WriteFile(path.Join(*serverPath, *secretName), sealed, os.ModePerm)
		if err != nil {
			log.Fatal("Could not write out sealed secret:", err)
		}
	} else {
		sealed, err := ioutil.ReadFile(path.Join(*serverPath, *secretName))
		if err != nil {
			log.Fatal("Could not read sealed secret:", err)
		}
		secret, _, err = tao.Parent().Unseal(sealed)
	}

	t := &TaoServer{
		TaoName:         taoName.String(),
		Secret:          secret,
		ProgramFilePath: serverPath,
	}
	return t
}

func main() {

}
