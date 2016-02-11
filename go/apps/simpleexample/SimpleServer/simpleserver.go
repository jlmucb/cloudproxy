// Copyright (c) 2014, Google, Inc.  All rights reserved.
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
// File: simpleserver.go

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net"

	"github.com/jlmucb/cloudproxy/apps/simplecommon"
	tao "github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
	"github.com/jlmucb/cloudproxy/util"
)

var simplecfg = flag.String("../simpledomain/tao.config", "../simpledomain/tao.config", "path to simple tao configuration")
var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var serverAddr string

func HandleServiceRequest(ms *util.MessageStream, serverProgramData *simplecommon.TaoProgramData,
	clientProgramName, req string) (bool, error) {
	return true, nil
}

func serviceThead(ms *util.MessageStream, clientProgramName string,
		  serverProgramData *simplecommon.TaoProgramData) {

	for {
		log.Printf("clientServiceThead: ReadString\n")
		req, err := ms.ReadString()
		if err != nil {
			return
		}
		terminate, _ := HandleServiceRequest(ms, serverProgramData,
			          clientProgramName, req)
		if terminate {
			break
		}
	}
	log.Printf("simpleserver: client thread terminating\n")
}


func server(serverAddr string, serverProgramData *simplecommon.TaoProgramData) {

	var sock net.Listener

	// Service client connections.
	for {
		conn, err := sock.Accept()
		if err != nil {
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
		if clientName == nil {
			log.Printf("server: can't get client name\n")
			continue
			}
		log.Printf("server, peer client name: %s\n", clientName)
		ms := util.NewMessageStream(conn)
		go serviceThead(ms, clientName, serverProgramData)
	}
}

func main() {

	var serverProgramData simplecommon.TaoProgramData

	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort


	// Load domain info for this domain
	// This was initialized by TODO.
	if !TaoParadigm(*simplecfg, &serverProgramData) {
		log.Fatalln("simpleclient: Can't establish Tao")
	}

	err = server(serverAddr, &serverProgramData)
	if err != nil {
		log.Printf("simpleserver: server error\n")
	}
	log.Printf("simpleserver: done\n")
}
