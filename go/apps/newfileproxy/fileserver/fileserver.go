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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"path"

	taosupport "github.com/jlmucb/cloudproxy/go/support_libraries/tao_support"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util"

	"github.com/jlmucb/cloudproxy/go/apps/newfileproxy/common"
	"github.com/jlmucb/cloudproxy/go/apps/newfileproxy/resourcemanager"
)

var caAddr = flag.String("caAddr", "localhost:8124", "The address to listen on")
var simpleCfg = flag.String("domain_config",
	"./tao.config",
	"path to fileproxy tao configuration")
var fileServerPath = flag.String("path",
	"./FileServer",
	"path to Server files")
var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var useSimpleDomainService = flag.Bool("use_simpledomainservice", true,
	"whether to use simple domain service")
var serverAddr string

// Handles service request, req and return response over channel (ms).
func serviceThead(ms *util.MessageStream, clientProgramName string,
	serverData *common.ServerData, connectionData *common.ServerConnectionData,
	serverProgramData *taosupport.TaoProgramData) {
	for {
		req, err := common.GetMessage(ms)
		if err != nil {
			return
		}
		// log.Printf("serviceThread, got message: ")
		// common.PrintMessage(req)
		common.DoRequest(ms, serverData, connectionData, req)
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
		connectionData := new(common.ServerConnectionData)
		go serviceThead(ms, clientName, serverData, connectionData, serverProgramData)
	}
}

func main() {

	// main is very similar to the initial parts of main in simpleclient,
	// See the comments there.
	var serverProgramData taosupport.TaoProgramData
	defer serverProgramData.ClearTaoProgramData()

	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort

	// Load domain info for this domain
	err := taosupport.TaoParadigm(simpleCfg, fileServerPath, "ECC-P-256.aes128.hmacaes256",
		*useSimpleDomainService, *caAddr, &serverProgramData)
	if err != nil {
		log.Fatalln("fileserver: Can't establish Tao", err)
	}
	log.Printf("newfileserver name is %s\n", serverProgramData.TaoName)

	// Get or initialize encryption keys for table
	fileSecrets := make([]byte, 32)
	secretsFileName := path.Join(*fileServerPath, "FileSecrets.bin")
	encryptedFileSecrets, err := ioutil.ReadFile(secretsFileName)
	if err != nil {
		rand.Read(fileSecrets)
		// Save encryption keys for table
		encryptedFileSecrets, err = taosupport.Protect(serverProgramData.ProgramSymKeys, fileSecrets[:])
		if err != nil {
			fmt.Printf("fileserver: Error protecting data\n")
		}
		err = ioutil.WriteFile(secretsFileName, encryptedFileSecrets, 0666)
		if err != nil {
			fmt.Printf("fileserver: error saving retrieved secret\n")
		}
	} else {
		fileSecrets, err = taosupport.Unprotect(serverProgramData.ProgramSymKeys, encryptedFileSecrets)
		if err != nil {
			fmt.Printf("fileserver: Error protecting data\n")
		}
	}

	// Initialize serverData
	serverData := new(common.ServerData)
	if serverData == nil {
		fmt.Printf("fileserver: error parsing policy certificate\n")
		return
	}

	serverData.PolicyCert = serverProgramData.PolicyCert
	serverData.PolicyCertificate, err = x509.ParseCertificate(serverData.PolicyCert)
	if err != nil {
		fmt.Printf("fileserver: error parsing policy certificate\n")
		return
	}
	serverData.ResourceManager = new(resourcemanager.ResourceMasterInfo)
	serverData.FileSecrets = fileSecrets[:]
	serviceName := "fileserver"
	serverData.ResourceManager.ServiceName = &serviceName
	serverData.ResourceManager.BaseDirectoryName = fileServerPath
	serverData.PolicyCert = serverProgramData.PolicyCert

	fmt.Printf("Initializing Table\n")
	// Read resource table.
	tableFileName := path.Join(*fileServerPath, "EncryptedTable.bin")
	if !resourcemanager.ReadTable(serverData.ResourceManager, tableFileName, fileSecrets[:],
		&serverData.ResourceMutex) {
		fmt.Printf("fileserver: error parsing policy certificate\n")
		return
	}

	server(serverAddr, serverData, &serverProgramData)
	log.Printf("fileserver: done\n")
}
