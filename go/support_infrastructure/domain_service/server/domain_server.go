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
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"

	"github.com/jlmucb/cloudproxy/go/support_infrastructure/domain_service"
)

var machineName = "Encode Machine Information"

var hostName = &auth.Prin{
	Type: "DummyPrin",
	Key:  auth.Str("hostHash")}

var programName = &auth.Prin{
	Type: "DummyPrin",
	Key:  auth.Str("programHash")}

var network = flag.String("network", "tcp", "The network to use for connections")
var addr = flag.String("addr", "localhost:8124", "The address to listen on")
var domainPass = flag.String("password", "xxx", "The domain password")
var configPath = flag.String("config", "/Domains/domainserver/tao.config", "The Tao domain config")

var serialNumber = 0

func loadDomain() (*tao.Domain, *x509.CertPool, error) {
	var cfg tao.DomainConfig
	d, err := ioutil.ReadFile(*configPath)
	if err != nil {
		return nil, nil, err
	}
	if err := proto.UnmarshalText(string(d), &cfg); err != nil {
		return nil, nil, err
	}
	domain, err := tao.CreateDomain(cfg, *configPath, []byte(*domainPass))
	if domain == nil {
		log.Printf("domainserver: no domain path - %s, pass - %s, err - %s\n",
			*configPath, *domainPass, err)
		return nil, nil, err
	} else if err != nil {
		log.Printf("domainserver: Couldn't load the config path %s: %s\n",
			*configPath, err)
		return nil, nil, err
	}
	log.Printf("domainserver: Loaded domain\n")
	err = domain.Guard.Authorize(*hostName, "Host", []string{})
	if err != nil {
		return nil, nil, err
	}
	err = domain.Guard.Authorize(*programName, "Execute", []string{})
	if err != nil {
		return nil, nil, err
	}
	machinePrin := auth.Prin{Type: "MachineInfo", Key: auth.Str(machineName)}
	err = domain.Guard.Authorize(machinePrin, "Root", []string{})
	if err != nil {
		return nil, nil, err
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(domain.Keys.Cert)
	return domain, certPool, nil
}

func main() {
	flag.Parse()
	domain, rootCerts, err := loadDomain()
	if err != nil {
		log.Fatalln("domain_server: could not load domain:", err)
	}
	ln, err := net.Listen(*network, *addr)
	if err != nil {
		log.Fatalln("domain_server: could not listen at port:", err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatalln("domain_server: could not accept connection:", err)
		}
		// switch case
		ms := util.NewMessageStream(conn)
		var request domain_service.DomainServiceRequest
		if err := ms.ReadMessage(&request); err != nil {
			log.Printf("domain_server: Couldn't read request from channel: %s\n", err)
			continue
		}
		switch *request.Type {
		case domain_service.DomainServiceRequest_DOMAIN_CERT_REQUEST:
			_, key, prog, err := domain_service.VerifyHostAttestation(
				request.GetSerializedHostAttestation(), domain, rootCerts)
			if err != nil {
				log.Printf("domain_server: Error verifying host att: %s\n", err)
				sendError(err, ms)
				continue
			}
			att, err := domain_service.GenerateProgramCert(
				domain, serialNumber, prog, key)
			if err != nil {
				log.Printf("domain_server: Error generating program cert: %s\n", err)
				sendError(err, ms)
				continue
			}
			serAtt, err := proto.Marshal(att)
			if err != nil {
				log.Printf("domain_server: Error marshalling program cert: %s\n", err)
				sendError(err, ms)
				continue
			}
			resp := &domain_service.DomainServiceResponse{
				SerializedDomainAttestation: serAtt}
			if _, err := ms.WriteMessage(resp); err != nil {
				log.Printf("domain_server: Error sending cert on the channel: %s\n ",
					err)
				continue
			}
		case domain_service.DomainServiceRequest_MANAGE_POLICY:
		case domain_service.DomainServiceRequest_REVOKE_CERTIFICATE:
		}
	}
}

func sendError(err error, ms *util.MessageStream) {
	errStr := err.Error()
	resp := &domain_service.DomainServiceResponse{ErrorMessage: &errStr}
	if _, err := ms.WriteMessage(resp); err != nil {
		log.Printf("domain_server: Error sending resp on the channel: %s\n ", err)
	}
}
