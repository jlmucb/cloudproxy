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
	"crypto/rand"
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
var configPath = flag.String("config", "../server/state/server.config", "The server config")

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
	key1Val := createKeyVal()
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
	directive, err = secret_disclosure.CreateSecretDisclosureDirective(program1Key, program1,
		program2, secret_disclosure.CreatePredicate, &key1Id)
	failOnError(err)
	log.Println("Successfully created directive authorizing Program2 to create under key1.")

	// Program 2 creates sub secret.
	key2Name := "Key 2"
	key2Val := createKeyVal()
	err = secret_service.CreateSecret(key2Name, epoch, "key", key2Val, &key1Name, &epoch,
		[]secret_disclosure.DirectiveMessage{*directive}, *addr, domain.Keys.Cert,
		program2Key)
	failOnError(err)
	log.Println("Program 2 successfully created key2 under key1.")

	// Program 2 authorizes program 1 to write.
	key2Id := protected_objects.ObjectIdMessage{
		ObjName:  &key2Name,
		ObjEpoch: &epoch}
	directive, err = secret_disclosure.CreateSecretDisclosureDirective(program2Key, program2,
		program1, secret_disclosure.WritePredicate, &key2Id)
	failOnError(err)
	log.Println("Successfully created directive authorizing Program1 to write key2.")

	// Program 1 writes.
	key2NewVal := createKeyVal()
	err = secret_service.WriteSecret(key2Name, epoch, "key", key2NewVal,
		[]secret_disclosure.DirectiveMessage{*directive}, *addr, domain.Keys.Cert, program1Key)
	failOnError(err)
	log.Println("Program 1 successfully overwrote key2.")

	// Program 1 authorizes Program 3 to read subsecret. Fails.
	directive, err = secret_disclosure.CreateSecretDisclosureDirective(program1Key, program1,
		program3, secret_disclosure.ReadPredicate, &key2Id)
	failOnError(err)
	log.Println("Successfully created directive authorizing Program3 to read key2.")

	program3Key := createProgramKey(program3, domain)
	_, _, err = secret_service.ReadSecret(key2Name, epoch,
		[]secret_disclosure.DirectiveMessage{*directive}, *addr, domain.Keys.Cert, program3Key)
	if err == nil {
		log.Fatalln("Expected error but didn't get one: Program1 authorized read of key2.")
	}
	log.Println("Program1 not allowed to authorize read of key2, got error as expected.")

	// Program 2 authorizes Program 1 to own sub-secret.
	directive, err = secret_disclosure.CreateSecretDisclosureDirective(program2Key, program2,
		program1, secret_disclosure.OwnPredicate, &key2Id)
	failOnError(err)
	log.Println("Successfully created directive authorizing Program1 to own key2.")
	err = secret_service.ProcessDirectives([]secret_disclosure.DirectiveMessage{*directive},
		*addr, domain.Keys.Cert, program2Key)
	failOnError(err)
	log.Println("Program 2 authorized Program 1 to own key2.")

	// Program 1 authorizes Program 3 to read subsecret.
	directive, err = secret_disclosure.CreateSecretDisclosureDirective(program1Key, program1,
		program3, secret_disclosure.ReadPredicate, &key2Id)
	failOnError(err)
	log.Println("Successfully created directive authorizing Program3 to read key2.")

	typ, val, err = secret_service.ReadSecret(key2Name, epoch,
		[]secret_disclosure.DirectiveMessage{*directive}, *addr, domain.Keys.Cert, program3Key)
	failOnError(err)
	if *typ != "key" {
		log.Fatalf("Program 3 read wrong secret type. Expected key but got %v.", *typ)
	}
	if !bytes.Equal(val, key2NewVal) {
		log.Fatalf("Program 3 read wrong secret val. \nExpected: %v\nBut got: %v.",
			key2NewVal, val)
	}
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

func createKeyVal() []byte {
	keyVal := make([]byte, 32)
	_, err := rand.Read(keyVal)
	if err != nil {
		log.Fatalln("Error creating key values. Error: ", err)
	}
	return keyVal
}
