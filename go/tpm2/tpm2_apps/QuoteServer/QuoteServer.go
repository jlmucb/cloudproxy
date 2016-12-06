// Copyright (c) 2016, Google Inc. All rights reserved.
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

package main

import (
	"flag"
	"log"

	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tpm2/tpm2_apps"
)

var (
	network = flag.String("network", "tcp", "The network to use for connections")
	addr    = flag.String("addr", "localhost:8121", "The address to listen on")
	pass    = flag.String("pass", "xxx", "The password protecting the policy key")
	path    = flag.String("path", "./keys/", "The path to the keys")

	us      = "US"
	org     = "Google"
	details = tao.X509Details{
		Country:            &us,
		Organization:       &org,
		OrganizationalUnit: &org,
		CommonName:         &org,
	}
)

func main() {
	flag.Parse()
	s := tpm2_apps.NewQuoteServer(*network, *addr)
	err := s.HandleQuote(*pass, *path, details)
	if err != nil {
		log.Fatal(err)
	}
}
