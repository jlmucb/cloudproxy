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

package secret_service

// This provides the client stub for using the secret service.
// This code is relatively dull, all it does is marshal/serialize the
// secret service requests and responses.

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/support_libraries/secret_disclosure_support"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util"
)

func ProcessDirectives(directives []secret_disclosure.DirectiveMessage, addr string,
	policyCert *x509.Certificate, programKey *tao.Keys) error {
	var serDirectives [][]byte
	for _, directive := range directives {
		serDirective, err := proto.Marshal(&directive)
		if err != nil {
			return err
		}
		serDirectives = append(serDirectives, serDirective)
	}
	op := SecretServiceRequest_NOP
	request := SecretServiceRequest{
		Op:         &op,
		Directives: serDirectives,
	}
	ms, err := openTaoChannel(policyCert, programKey, &addr)
	if err != nil {
		return err
	}
	_, err = ms.WriteMessage(&request)
	if err != nil {
		return err
	}
	log.Printf("Sent NOP request to Secret Service at address %s.", addr)
	var response SecretServiceResponse
	err = ms.ReadMessage(&response)
	if err != nil {
		return err
	}
	log.Println("Got response from Secret Service.")

	if errStr := response.GetErrorMessage(); errStr != "" {
		return errors.New(errStr)
	}
	return nil
}

func ReadSecret(name string, epoch int32, directives []secret_disclosure.DirectiveMessage,
	addr string, policyCert *x509.Certificate, programKey *tao.Keys) (*string, []byte, error) {
	var serDirectives [][]byte
	for _, directive := range directives {
		serDirective, err := proto.Marshal(&directive)
		if err != nil {
			return nil, nil, err
		}
		serDirectives = append(serDirectives, serDirective)
	}
	op := SecretServiceRequest_READ
	request := SecretServiceRequest{
		Op:         &op,
		ObjName:    &name,
		ObjEpoch:   &epoch,
		Directives: serDirectives,
	}
	ms, err := openTaoChannel(policyCert, programKey, &addr)
	if err != nil {
		return nil, nil, err
	}
	_, err = ms.WriteMessage(&request)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("Sent READ request to Secret Service at address %s.", addr)
	var response SecretServiceResponse
	err = ms.ReadMessage(&response)
	if err != nil {
		return nil, nil, err
	}
	log.Println("Got response from Secret Service.")

	if errStr := response.GetErrorMessage(); errStr != "" {
		return nil, nil, errors.New(errStr)
	}
	typ := response.GetSecretType()
	return &typ, response.GetSecretVal(), nil
}

func WriteSecret(name string, epoch int32, newType string, newVal []byte,
	directives []secret_disclosure.DirectiveMessage, addr string, policyCert *x509.Certificate,
	programKey *tao.Keys) error {
	var serDirectives [][]byte
	for _, directive := range directives {
		serDirective, err := proto.Marshal(&directive)
		if err != nil {
			return err
		}
		serDirectives = append(serDirectives, serDirective)
	}
	op := SecretServiceRequest_WRITE
	request := SecretServiceRequest{
		Op:         &op,
		ObjName:    &name,
		ObjEpoch:   &epoch,
		NewType:    &newType,
		NewVal:     newVal,
		Directives: serDirectives,
	}
	ms, err := openTaoChannel(policyCert, programKey, &addr)
	if err != nil {
		return err
	}
	_, err = ms.WriteMessage(&request)
	if err != nil {
		return err
	}
	log.Printf("Sent WRITE request to Secret Service at address %s.", addr)
	var response SecretServiceResponse
	err = ms.ReadMessage(&response)
	if err != nil {
		return err
	}
	log.Println("Got response from Secret Service.")

	if errStr := response.GetErrorMessage(); errStr != "" {
		return errors.New(errStr)
	}
	return nil
}

func CreateSecret(name string, epoch int32, newType string, newVal []byte, protectorName *string,
	protectorEpoch *int32, directives []secret_disclosure.DirectiveMessage, addr string,
	policyCert *x509.Certificate, programKey *tao.Keys) error {
	var serDirectives [][]byte
	for _, directive := range directives {
		serDirective, err := proto.Marshal(&directive)
		if err != nil {
			return err
		}
		serDirectives = append(serDirectives, serDirective)
	}
	op := SecretServiceRequest_CREATE
	request := SecretServiceRequest{
		Op:             &op,
		ObjName:        &name,
		ObjEpoch:       &epoch,
		NewType:        &newType,
		NewVal:         newVal,
		ProtectorName:  protectorName,
		ProtectorEpoch: protectorEpoch,
		Directives:     serDirectives,
	}
	ms, err := openTaoChannel(policyCert, programKey, &addr)
	if err != nil {
		return err
	}
	_, err = ms.WriteMessage(&request)
	if err != nil {
		return err
	}
	log.Printf("Sent CREATE request to Secret Service at address %s.", addr)
	var response SecretServiceResponse
	err = ms.ReadMessage(&response)
	if err != nil {
		return err
	}
	log.Println("Got response from Secret Service.")

	if errStr := response.GetErrorMessage(); errStr != "" {
		return errors.New(errStr)
	}
	return nil
}

func DeleteSecret(name string, epoch int32, directives []secret_disclosure.DirectiveMessage,
	addr string, policyCert *x509.Certificate, programKey *tao.Keys) error {
	var serDirectives [][]byte
	for _, directive := range directives {
		serDirective, err := proto.Marshal(&directive)
		if err != nil {
			return err
		}
		serDirectives = append(serDirectives, serDirective)
	}
	op := SecretServiceRequest_CREATE
	request := SecretServiceRequest{
		Op:         &op,
		ObjName:    &name,
		ObjEpoch:   &epoch,
		Directives: serDirectives,
	}
	ms, err := openTaoChannel(policyCert, programKey, &addr)
	if err != nil {
		return err
	}
	_, err = ms.WriteMessage(&request)
	if err != nil {
		return err
	}
	log.Printf("Sent DELETE request to Secret Service at address %s.", addr)
	var response SecretServiceResponse
	err = ms.ReadMessage(&response)
	if err != nil {
		return err
	}
	log.Println("Got response from Secret Service.")

	if errStr := response.GetErrorMessage(); errStr != "" {
		return errors.New(errStr)
	}
	return nil
}

// Establishes the Tao Channel for a client using the Program Key.
// This program does all the standard client side channel negotiation.
// After negotiation is complete.  ms is the bi-directional confidentiality and
// integrity protected channel.  OpenTaoChannel returns the stream (ms) for subsequent reads
// and writes.
func openTaoChannel(policyCert *x509.Certificate, programKey *tao.Keys,
	serverAddr *string) (*util.MessageStream, error) {

	pool := x509.NewCertPool()
	pool.AddCert(policyCert)

	// Open the Tao Channel using the Program key.
	tlsc, err := tao.EncodeTLSCert(programKey)
	if err != nil {
		return nil, err
	}
	conn, err := tls.Dial("tcp", *serverAddr, &tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: false,
	})
	if err != nil {
		return nil, errors.New(fmt.Sprintf(
			"OpenTaoChannel: Can't establish channel. Error : %v", err))
	}
	// Stream for Tao Channel.
	ms := util.NewMessageStream(conn)
	return ms, nil
}
