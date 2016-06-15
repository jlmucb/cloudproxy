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
	"bytes"
	"flag"
	"log"

	"github.com/jlmucb/cloudproxy/go/support_infrastructure/secret_service"
	"github.com/jlmucb/cloudproxy/go/support_libraries/protected_objects"
	"github.com/jlmucb/cloudproxy/go/support_libraries/secret_disclosure_support"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

var program1 = &auth.Prin{
	Type: "program",
	Key:  auth.Str("programHash1")}
var program2 = &auth.Prin{
	Type: "program",
	Key:  auth.Str("programHash2")}
var program3 = &auth.Prin{
	Type: "program",
	Key:  auth.Str("programHash3")}

var network = flag.String("network", "tcp", "The network to use for connections")
var addr = flag.String("addr", "localhost:8124", "The address to listen on")

var domainPass = flag.String("password", "xxx", "The domain password")
var configPath = flag.String("config", "../server/state/tao.config", "The Tao domain config")

func main() {

	log.Println("Starting test server...")
	domain, err := tao.LoadDomain(*configPath, []byte(*domainPass))
	if domain == nil {
		log.Fatalf("domainserver: no domain path - %s, pass - %s, err - %s\n",
			*configPath, *domainPass, err)
	}
	failOnError(err)
	log.Println("Domain key loaded.")
	program1Key := createProgramKey(program1, domain)

	// Create directive authorizing program 1 to create secrets.
	kPrin := domain.Keys.SigningKey.ToPrincipal()
	directive, err := secret_disclosure.CreateSecretDisclosureDirective(domain.Keys, &kPrin,
		program1, secret_disclosure.CreatePredicate, nil)
	failOnError(err)
	log.Println("Successfully created directive authorizing Program1 to create under root.")

	// Send create request from program 1.
	key1Name := "MyKey"
	epoch := int32(1)
	key1Val := []byte("I am a key 1")
	err = secret_service.CreateSecret(key1Name, epoch, "key", key1Val, nil, nil,
		[]secret_disclosure.DirectiveMessage{*directive}, *addr, domain.Keys.Cert,
		program1Key)
	failOnError(err)
	log.Println("Program1 successfully creates key1.")

	// Send create request from program 2. Fails.
	program2Key := createProgramKey(program2, domain)
	err = secret_service.CreateSecret(key1Name, epoch, "key", key1Val, nil, nil,
		[]secret_disclosure.DirectiveMessage{*directive}, *addr, domain.Keys.Cert,
		program2Key)
	if err == nil {
		log.Fatalln("Program2 created a secret without error, but it was not authorized.")
	}
	log.Println("Program 2 denied request to create, as expected.")

	// Program 1 authorizes program 2 for read.
	key1Id := protected_objects.ObjectIdMessage{
		ObjName:  &key1Name,
		ObjEpoch: &epoch}
	directive, err = secret_disclosure.CreateSecretDisclosureDirective(program1Key, program1,
		program2, secret_disclosure.ReadPredicate, &key1Id)
	failOnError(err)
	log.Println("Successfully created directive authorizing Program2 to read key1.")
	err = secret_service.ProcessDirectives([]secret_disclosure.DirectiveMessage{*directive},
		*addr, domain.Keys.Cert, program1Key)
	failOnError(err)
	log.Println("Program 1 authorized Program 2 to read key1.")

	// Program 2 reads.
	typ, val, err := secret_service.ReadSecret(key1Name, epoch,
		[]secret_disclosure.DirectiveMessage{}, *addr, domain.Keys.Cert, program2Key)
	failOnError(err)
	if *typ != "key" {
		log.Fatalf("Program 2 read wrong secret type. Expected key but got %v.", *typ)
	}
	if !bytes.Equal(val, key1Val) {
		log.Fatalf("Program 2 read wrong secret val. \nExpected: %v\nBut got: %v.",
			key1Val, val)
	}
	// Program 1 authorizes program 2 for create.
	// Program 2 creates sub secret.
	// Program 2 authorizes program 1 to write.
	// Program 1 writes.
	// Program 1 authorizes Program 3 to read subsecret. Fails.
	// Program 2 authorizes Program 1 to own sub-secret.
	// Program 1 authorizes Program 3 to read subsecret.
}

func failOnError(err error) {
	if err != nil {
		log.Fatalf("Terminating due to error: %v", err)
	}
}

func createProgramKey(program *auth.Prin, domain *tao.Domain) *tao.Keys {
	programKey, err := tao.NewTemporaryKeys(tao.Signing)
	failOnError(err)
	programName := tao.NewX509Name(domain.Config.X509Info)
	programName.OrganizationalUnit = []string{program.String()}
	programCert, err := domain.Keys.SigningKey.CreateSignedX509(domain.Keys.Cert, 0,
		programKey.VerifyingKey, programName)
	failOnError(err)
	programKey.Cert = programCert
	return programKey
}
