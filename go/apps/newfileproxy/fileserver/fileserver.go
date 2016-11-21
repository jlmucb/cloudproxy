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
//
// File: fileserver.go

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/jlmucb/cloudproxy/go/apps/simpleexample/taosupport"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util"

	"github.com/jlmucb/cloudproxy/go/apps/newfileproxy/common"
	"github.com/jlmucb/cloudproxy/go/apps/newfileproxy/resourcemanager"
)

var simpleCfg = flag.String("domain_config",
	"./tao.config",
	"path to simple tao configuration")
var simpleServerPath = flag.String("path", 
	"./FileServer",
	"path to Server files")
var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var serverAddr string

// Handles service request, req and return response over channel (ms).
func serviceThead(ms *util.MessageStream, clientProgramName string,
	// serverData common.ServerData
	serverProgramData *taosupport.TaoProgramData) {

	for {
		req, err := taosupport.GetRequest(ms)
		if err != nil {
			return
		}
		log.Printf("serviceThread, got message: ")
		taosupport.PrintMessage(req)

		// DoRequest(ms *util.MessageStream, serverData *ServerData, req []byte)

	}
	log.Printf("fileserver: client thread terminating\n")
}

// This is the server. It implements the server Tao Channel negotiation corresponding
// to the client's taosupport.OpenTaoChannel.
func server(serverAddr string, serverData *common.ServerData, serverProgramData *taosupport.TaoProgramData) {

	var sock net.Listener

	// Set up the single root certificate for channel negotiation which is the
	// policy key cert.
	pool := x509.NewCertPool()
	policyCert, err := x509.ParseCertificate(serverProgramData.PolicyCert)
	if err != nil {
		log.Printf("fileserver, can't parse policyCert: ", err, "\n")
		return
	}
	// Make the policy cert the unique root of the verification chain.
	pool.AddCert(policyCert)
	tlsc, err := tao.EncodeTLSCert(&serverProgramData.ProgramKey)
	if err != nil {
		log.Printf("fileserver, encode error: ", err, "\n")
		return
	}
	conf := &tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: false,
		ClientAuth:         tls.RequireAnyClientCert,
	}

	// Listen for clients.
	log.Printf("fileserver: Listening\n")
	sock, err = tls.Listen("tcp", serverAddr, conf)
	if err != nil {
		log.Printf("fileserver, listen error: ", err, "\n")
		return
	}

	// Service client connections.
	for {
		log.Printf("server: at accept\n")
		conn, err := sock.Accept()
		if err != nil {
			fmt.Printf("fileserver: can't accept connection: %s\n", err.Error())
			log.Printf("server: can't accept connection: %s\n", err.Error())
			continue
		}
		var clientName string
		err = conn.(*tls.Conn).Handshake()
		if err != nil {
			log.Printf("server: TLS handshake failed\n")
			continue
		}
		peerCerts := conn.(*tls.Conn).ConnectionState().PeerCertificates
		if peerCerts == nil {
			log.Printf("server: can't get peer list\n")
			continue
		}
		peerCert := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
		if peerCert.Raw == nil {
			log.Printf("server: can't get peer cert\n")
			continue
		}
		if peerCert.Subject.OrganizationalUnit == nil {
			log.Printf("server: can't get peer name\n")
			continue
		}
		clientName = peerCert.Subject.OrganizationalUnit[0]
		log.Printf("server, peer client name: %s\n", clientName)
		ms := util.NewMessageStream(conn)

		// At this point the handshake is complete and we fork a service thread
		// to communicate with this simpleclient.  ms is the bi-directional
		// confidentiality and integrity protected channel corresponding to the
		// channel opened by OpenTaoChannel.
		go serviceThead(ms, clientName, serverProgramData)
	}
}

func main() {

	// main is very similar to the initial parts of main in simpleclient,
	// see the comments there.
	var serverProgramData taosupport.TaoProgramData
	defer taosupport.ClearTaoProgramData(&serverProgramData)

	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort

	// Load domain info for this domain
	err := taosupport.TaoParadigm(simpleCfg, simpleServerPath, &serverProgramData)
	if err != nil {
		log.Fatalln("fileserver: Can't establish Tao", err)
	}
	log.Printf("fileserver name is %s\n", serverProgramData.TaoName)

	// Get or initialize encryption keys for table

	// Save encryption keys for table

	// Initialize serverData
	serverData := new(common.ServerData)
	if serverData == nil {
	}

	serverData.PolicyCert = serverProgramData.PolicyCert
	serverData.PolicyCertificate, err = x509.ParseCertificate(serverData.PolicyCert)
	if err != nil {
	}
	serverData.Principals = new(common.AuthentictedPrincipals)
	serverData.ResourceManager = new(resourcemanager.ResourceMasterInfo)

	// Read resource table.

	server(serverAddr, serverData, &serverProgramData)
	log.Printf("fileserver: done\n")
}
