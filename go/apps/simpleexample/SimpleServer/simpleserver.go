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

	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/apps/simpleexample/taosupport"
	"github.com/jlmucb/cloudproxy/go/util"
)

var simpleCfg = flag.String("tao.config",
	"/Domains/domain.simpleexample/tao.config",
	"path to simple tao configuration")
var simpleServerPath = flag.String("/Domains/domain.simpleexample/SimpleServer",
			"/Domains/domain.simpleexample/SimpleServer",
			"path to Server files")
var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var serverAddr string
// Handle service request, req and return response over channel (ms).
// This handles the one valid service request: "SecretRequest"
// and terminates the channel after the first successful request
// which is not generally what would happen in most channels.
// Note that in the future, we might want to use grpc rather than custom
// service request/response buffers but we don't want to introduce complexity
// into this example.  The single request response buffer is defined in
// taosupport/taosupport.proto.
func HandleServiceRequest(ms *util.MessageStream, serverProgramData *taosupport.TaoProgramData,
	clientProgramName string, req *taosupport.SimpleMessage) (bool, error) {

	//  The somewhat boring secret is the corresponding simpleclient's program name || 43
	secret := clientProgramName + "43"

	if *req.RequestType == "SecretRequest"  {
		req.Data = append(req.Data, []byte(secret))
		taosupport.SendResponse(ms, req)
		log.Printf("HandleServiceRequest response buffer: ")
		taosupport.PrintMessage(req)
		return true, nil
	} else {
		log.Printf("HandleServiceRequest response is bad request\n")
		errmsg := "BadRequest"
		req.Err = &errmsg
		return false, nil
	}
}

func serviceThead(ms *util.MessageStream, clientProgramName string,
	serverProgramData *taosupport.TaoProgramData) {

	for {
		req, err :=  taosupport.GetRequest(ms)
		if err != nil {
			return
		}
		log.Printf("serviceThread, got message: ");
		taosupport.PrintMessage(req)

		terminate, _ := HandleServiceRequest(ms, serverProgramData,
			clientProgramName, req)
		if terminate {
			break
		}
	}
	log.Printf("simpleserver: client thread terminating\n")
}

// This is the server. It implements the server Tao Channel negotiation corresponding
// to the client's taosupport.OpenTaoChannel.  It's possible we should move this into
// taosupport/taosupport.go since it should not vary very much from implementation to
// implementation.
func server(serverAddr string, serverProgramData *taosupport.TaoProgramData) {

	var sock net.Listener

	// Set up the single root certificate for channel negotiation which is the
	// policy key cert.
	pool := x509.NewCertPool()
	policyCert, err := x509.ParseCertificate(serverProgramData.PolicyCert)
	if err != nil {
		log.Printf("simpleserver, can't parse policyCert: ", err, "\n")
		return
	}
	// Make the policy cert the unique root of the verification chain.
	pool.AddCert(policyCert)
	tlsc, err := tao.EncodeTLSCert(&serverProgramData.ProgramKey)
	if err != nil {
		log.Printf("simpleserver, encode error: ", err, "\n")
		return
	}
	conf := &tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: false,
		ClientAuth:         tls.RequireAnyClientCert,
	}

	// Listen for clients.
	log.Printf("simpleserver: Listening\n")
	sock, err = tls.Listen("tcp", serverAddr, conf)
	if err != nil {
		log.Printf("simpleserver, listen error: ", err, "\n")
		return
	}

	// Service client connections.
	for {
		log.Printf("server: at accept\n")
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

	// main is very similar to the initial parts on main in simpleclient.
	// see the comments there.
	var serverProgramData taosupport.TaoProgramData
	defer taosupport.ClearTaoProgramData(&serverProgramData)

	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort

	// Load domain info for this domain
	if taosupport.TaoParadigm(simpleCfg, simpleServerPath, &serverProgramData) !=
			nil {
		log.Fatalln("simpleserver: Can't establish Tao")
	}
	log.Printf("simpleserver name is %s\n", serverProgramData.TaoName)

	server(serverAddr, &serverProgramData)
	log.Printf("simpleserver: done\n")
}
