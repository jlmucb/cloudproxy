// Copyright (c) 2016, Google Inc. All rights reserved.
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

// this is an adapted version of the server code in the roughtime for cloudproxy
// biggest difference is probably the listening
package main

import (
	"crypto/x509/pkix"
	"flag"
	"log"

	"github.com/jlmucb/cloudproxy/go/apps/roughtime"
	"github.com/jlmucb/cloudproxy/go/tao"
)

var (
	port       = flag.Int("port", 5333, "Port number to listen on")
	configPath = flag.String("config", "tao.config", "Path to domain configuration file.")
)

// x509 identity.
var x509Identity pkix.Name = pkix.Name{
	Organization:       []string{"Google Inc."},
	OrganizationalUnit: []string{"Cloud Security"},
}

func main() {
	flag.Parse()

	s, err := roughtime.NewServer(*configPath, "tcp", *port,
		&x509Identity, tao.Parent())
	if err != nil {
		log.Fatal(err)
	}
	err = s.ServeForever()
	if err != nil {
		log.Fatal(err)
	}
}
