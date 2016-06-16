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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/support_infrastructure/secret_service"
	"github.com/jlmucb/cloudproxy/go/support_libraries/protected_objects"
	directive_support "github.com/jlmucb/cloudproxy/go/support_libraries/secret_disclosure_support"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

var addr = flag.String("addr", "localhost:8124", "The address to listen on")

var domainPass = flag.String("password", "xxx", "The domain password")
var configPath = flag.String("config", "./tao.config", "The server config")

var initServerFlag = flag.Bool("init", false, "To create new server from specified config.")

var secretServiceName = "The Secret Service"
var rootName = "Root Object"
var epoch = int32(1)

var state *secret_service.ServerData

func main() {
	flag.Parse()
	var err error
	if *initServerFlag {
		log.Println("Creating new server...")
		state, err = secret_service.InitState(*configPath, *domainPass, secretServiceName)
		if err != nil {
			log.Fatalln("Error creating new server.", err)
		}
	} else {
		log.Println("Loading domain info...")
		state, err = secret_service.LoadState(*configPath, *domainPass)
		if err != nil {
			log.Fatalln("Error loading server.", err)
		}
	}
	server(*addr)
	log.Printf("secretserver: done\n")
}

// This is the server. It implements the server Tao Channel negotiation corresponding
// to the client's taosupport.OpenTaoChannel.  It's possible we should move this into
// taosupport/taosupport.go since it should not vary very much from implementation to
// implementation.
func server(serverAddr string) {

	var sock net.Listener

	// Set up the single root certificate for channel negotiation which is the
	// policy key cert.
	pool := x509.NewCertPool()
	// Make the policy cert the unique root of the verification chain.
	pool.AddCert(state.Domain.Keys.Cert)
	tlsc, err := tao.EncodeTLSCert(state.EncKey)
	if err != nil {
		log.Printf("secretserver, encode error: %s\n", err)
		return
	}
	conf := &tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: false,
		ClientAuth:         tls.RequireAnyClientCert,
	}

	// Listen for clients.
	log.Printf("secretserver: Listening\n")
	sock, err = tls.Listen("tcp", serverAddr, conf)
	if err != nil {
		log.Printf("secretserver, listen error: %s\n", err)
		return
	}

	// Service client connections.
	for {
		log.Printf("secretserver: at accept\n")
		conn, err := sock.Accept()
		if err != nil {
			log.Printf("secretserver: can't accept connection: %s\n", err.Error())
			continue
		}
		var clientName string
		err = conn.(*tls.Conn).Handshake()
		if err != nil {
			log.Printf("secretserver: TLS handshake failed\n")
			continue
		}
		peerCerts := conn.(*tls.Conn).ConnectionState().PeerCertificates
		if peerCerts == nil || len(peerCerts) == 0 {
			log.Printf("secretserver: can't get peer list\n")
			continue
		}
		peerCert := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
		if peerCert == nil {
			log.Printf("secretserver: can't get peer cert\n")
			continue
		}
		if ou := peerCert.Subject.OrganizationalUnit; ou == nil || len(ou) == 0 {
			log.Printf("secretserver: can't get peer name\n")
			continue
		}
		clientName = peerCert.Subject.OrganizationalUnit[0]
		log.Printf("secretserver: peer client name: %s\n", clientName)
		ms := util.NewMessageStream(conn)

		// At this point the handshake is complete and we fork a service thread
		// to communicate with this simpleclient.  ms is the bi-directional
		// confidentiality and integrity protected channel corresponding to the
		// channel opened by OpenTaoChannel.
		go serviceThread(ms, clientName)
	}
}

func serviceThread(ms *util.MessageStream, clientName string) {
	// Read in request.
	var request secret_service.SecretServiceRequest
	if err := ms.ReadMessage(&request); err != nil {
		log.Printf("secretserver: could not read request from channel.\nError: %v\n", err)
		sendError(errors.New(fmt.Sprintf(
			"Error reading request. Error: %v", err)), ms)
		return
	}
	log.Println("secretserver: got request.")

	// Process all directives.
	for i, directiveBytes := range request.Directives {
		var directive directive_support.DirectiveMessage
		err := proto.Unmarshal(directiveBytes, &directive)
		if err != nil {
			errStr := fmt.Sprintf(
				"Error unmarshalling directive number %d in request. Error: %v",
				i, err)
			log.Println("secretserver: " + errStr)
			sendError(errors.New(errStr), ms)
			return
		}
		err = directive_support.ProcessDirectiveAndUpdateGuard(state.Domain, &directive)
		if err != nil {
			errStr := fmt.Sprintf(
				"Error processing directive number %d in request. Error: %v",
				i, err)
			log.Println("secretserver: " + errStr)
			sendError(errors.New(errStr), ms)
			return
		}
		log.Printf("secretserver: successfully processed directive number %d in request.", i)
	}

	// Parse clientName into auth.Prin
	var client auth.Prin
	_, err := fmt.Sscanf(clientName, "%v", &client)
	if err != nil {
		errStr := fmt.Sprintf(
			"Error scanning client name %v as auth.Prin in request. \nError: %v",
			clientName, err)
		log.Println("secretserver: " + errStr)
		sendError(errors.New(errStr), ms)
		return
	}
	log.Printf("secretserver: successfully parsed client name as %v of type auth.Prin.",
		client.String())

	// Fulfll request.
	switch *request.Op {
	case secret_service.SecretServiceRequest_READ:
		if request.ObjName == nil || request.ObjEpoch == nil {
			errStr := "READ request has missing ObjName or ObjEpoch."
			log.Println("secretserver: " + errStr)
			sendError(errors.New(errStr), ms)
			return
		}
		id := protected_objects.ObjectIdMessage{
			ObjName: request.ObjName, ObjEpoch: request.ObjEpoch}
		log.Printf("secretserver: processing a READ request with following parameters."+
			"\nby: %v \nobjName: %v \nobjEpoch: %v",
			client.String(), *request.ObjName, *request.ObjEpoch)
		typ, val, err := secret_service.ReadObject(state.Lis, state.EncKey, &id, &client,
			state.Domain)
		if err != nil {
			errStr := fmt.Sprintf("Error reading object id %v. Error: %v",
				id.String(), err)
			log.Println("secretserver: " + errStr)
			sendError(errors.New(errStr), ms)
			return
		}
		resp := &secret_service.SecretServiceResponse{SecretType: typ, SecretVal: val}
		if _, err := ms.WriteMessage(resp); err != nil {
			log.Printf("secretserver: Error sending resp on the channel: %s\n ", err)
			return
		}
		log.Println("secretserver: successfully responded to READ request.")

	case secret_service.SecretServiceRequest_WRITE:
		if request.ObjName == nil || request.ObjEpoch == nil {
			errStr := "WRITE request has missing ObjName or ObjEpoch."
			log.Println("secretserver: " + errStr)
			sendError(errors.New(errStr), ms)
			return
		}
		id := protected_objects.ObjectIdMessage{
			ObjName: request.ObjName, ObjEpoch: request.ObjEpoch}
		log.Printf("secretserver: processing a WRITE request with following parameters."+
			"\nby: %v \nobjName: %v \nobjEpoch: %v",
			client.String(), *request.ObjName, *request.ObjEpoch)
		err = secret_service.WriteObject(state.Lis, state.EncKey, &id, &client, state.Domain,
			*request.NewType, request.NewVal)
		if err != nil {
			errStr := fmt.Sprintf("Error writing object id %v. Error: %v",
				id.String(), err)
			log.Println("secretserver: " + errStr)
			sendError(errors.New(errStr), ms)
			return
		}
		sendOk(ms)
		log.Println("secretserver: successfully responded to WRITE request.")

	case secret_service.SecretServiceRequest_CREATE:
		if request.ObjName == nil || request.ObjEpoch == nil {
			errStr := "CREATE request has missing ObjName or ObjEpoch."
			log.Println("secretserver: " + errStr)
			sendError(errors.New(errStr), ms)
			return
		}
		newId := protected_objects.ObjectIdMessage{
			ObjName: request.ObjName, ObjEpoch: request.ObjEpoch}
		// If request does not contain a protectorName or a protectorEpoch
		// then it is assumed that the intended protector is the root object.
		var protectorId *protected_objects.ObjectIdMessage
		if request.ProtectorName != nil && request.ProtectorEpoch != nil {
			protectorId = &protected_objects.ObjectIdMessage{
				ObjName: request.ProtectorName, ObjEpoch: request.ProtectorEpoch}
			log.Printf("secretserver: processing a CREATE request with parameters."+
				"\nby: %v \nnewName: %v \nnewEpoch: %v \nprotectorName:%v"+
				"\nprotectorEpoch: %v\n",
				client.String(), *request.ObjName, *request.ObjEpoch,
				*request.ProtectorName, *request.ProtectorEpoch)
		} else {
			log.Printf("secretserver: processing a CREATE request with parameters."+
				"\nby: %v \nnewName: %v \nnewEpoch: %v \nProtector: Root.\n",
				client.String(), *request.ObjName, *request.ObjEpoch)
		}
		err = secret_service.CreateObject(state.Lis, &newId, protectorId,
			state.RootPObj.ProtectedObjId, state.EncKey, &client, state.Domain,
			*request.NewType, request.NewVal)
		if err != nil {
			errStr := fmt.Sprintf("Error creating object id %v. Error: %v",
				newId.String(), err)
			log.Println("secretserver: " + errStr)
			sendError(errors.New(errStr), ms)
			return
		}
		sendOk(ms)
		log.Println("secretserver: successfully responded to CREATE request.")

	case secret_service.SecretServiceRequest_DELETE:
		if request.ObjName == nil || request.ObjEpoch == nil {
			errStr := "DELETE request has missing ObjName or ObjEpoch."
			log.Println("secretserver: " + errStr)
			sendError(errors.New(errStr), ms)
			return
		}
		id := protected_objects.ObjectIdMessage{
			ObjName: request.ObjName, ObjEpoch: request.ObjEpoch}
		log.Printf("secretserver: processing a DELETE request with following parameters."+
			"\nby: %v \nobjName: %v \nobjEpoch: %v",
			client.String(), *request.ObjName, *request.ObjEpoch)
		err = secret_service.DeleteObject(state.Lis, &id, &client, state.Domain)
		if err != nil {
			errStr := fmt.Sprintf("Error deleting object id %v. Error: %v",
				id.String(), err)
			log.Println("secretserver: " + errStr)
			sendError(errors.New(errStr), ms)
			return
		}
		sendOk(ms)
		log.Println("secretserver: successfully responded to DELETE request.")

	case secret_service.SecretServiceRequest_NOP:
		log.Println("secretserver: got NOP request. Doing nothing.")
		sendOk(ms)
	}
}

func sendError(err error, ms *util.MessageStream) {
	var errStr = ""
	if err != nil {
		errStr = err.Error()
	}
	resp := &secret_service.SecretServiceResponse{ErrorMessage: &errStr}
	if _, err := ms.WriteMessage(resp); err != nil {
		log.Printf("secretserver: Error sending resp on the channel: %s\n ", err)
	}
}

func sendOk(ms *util.MessageStream) {
	resp := &secret_service.SecretServiceResponse{}
	if _, err := ms.WriteMessage(resp); err != nil {
		log.Printf("secretserver: Error sending resp on the channel: %s\n ", err)
	}
}
