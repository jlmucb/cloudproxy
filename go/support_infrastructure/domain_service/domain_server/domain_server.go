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
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util"

	// "github.com/golang/crypto/ssh/terminal"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/jlmucb/cloudproxy/go/support_infrastructure/domain_service"
)

var network = flag.String("network", "tcp", "The network to use for connections")
var addr = flag.String("addr", "localhost:8124", "The address to listen on")
var domainPass = flag.String("pass", "", "The domain password")
var configTemplate = flag.String("config_template", "./domain_template", "The Tao domain template")
var configPath = flag.String("domain_config", "./tao.config", "The Tao domain config file")
var trustedEntitiesPath = flag.String("trusted_entities", "./TrustedEntities", "File containing trusted entities.")
var createDomainFlag = flag.Bool("create_domain", false, "To create new domain from specified config.")

var serialNumber = 0
var revokedCertificates []pkix.RevokedCertificate

func getPass() []byte {
	if domainPass == nil || *domainPass == "" {
		// Get the password from the user.
		fmt.Print("Policy key password: ")
		pwd, err := terminal.ReadPassword(syscall.Stdin)
		if err != nil {
			log.Fatalln("Can't get password", err)
		}
		fmt.Println()
		return pwd
	} else {
		fmt.Println("Warning: Passwords on the command line are not secure." +
			"Use -pass option only for testing.")
		return []byte(*domainPass)
	}
}

func createDomain() (*tao.Domain, *x509.CertPool, error) {
	var cfg tao.DomainTemplate
	d, err := ioutil.ReadFile(*configTemplate)
	if err != nil {
		return nil, nil, err
	}
	if err := proto.UnmarshalText(string(d), &cfg); err != nil {
		return nil, nil, err
	}
	pwd := getPass()
	domain, err := tao.CreateDomain(*cfg.Config, *configPath, pwd)
	if domain == nil {
		log.Printf("domainserver: no domain path - %s, pass - %s, err - %s\n",
			*configPath, pwd, err)
		return nil, nil, err
	} else if err != nil {
		log.Printf("domainserver: Couldn't load the config path %s: %s\n",
			*configPath, err)
		return nil, nil, err
	}
	log.Printf("domainserver: Created domain\n")
	err = domain.Save()
	if err != nil {
		return nil, nil, err
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(domain.Keys.Cert)
	return domain, certPool, nil
}

func loadDomain() (*tao.Domain, *x509.CertPool, error) {
	pwd := getPass()
	domain, err := tao.LoadDomain(*configPath, pwd)
	if domain == nil {
		log.Printf("domainserver: no domain path - %s, pass - %s, err - %s\n",
			*configPath, pwd, err)
		return nil, nil, err
	} else if err != nil {
		log.Printf("domainserver: Couldn't load the config path %s: %s\n",
			*configPath, err)
		return nil, nil, err
	}
	log.Printf("domainserver: Loaded domain\n")
	certPool := x509.NewCertPool()
	certPool.AddCert(domain.Keys.Cert)
	return domain, certPool, nil
}

func main() {
	flag.Parse()
	var domain *tao.Domain
	var err error
	if *createDomainFlag {
		log.Println("Creating new domain...")
		domain, _, err = createDomain()
	} else {
		log.Println("Loading domain info...")
		domain, _, err = loadDomain()
	}
	text, err := ioutil.ReadFile(*trustedEntitiesPath)
	if err != nil {
		log.Fatalf("Can't open trusted entities file: %s", *trustedEntitiesPath)
	}
	trustedEntities := domain_service.TrustedEntities{}
	err = proto.UnmarshalText(string(text), &trustedEntities)
	if err != nil {
		log.Fatalf("Can't parse trusted entities file: %s", *trustedEntitiesPath)
	}
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
			log.Println("Got Program cert request")
			_, kPrin, prog, err := domain_service.VerifyAttestation(request.GetSerializedHostAttestation(),
				domain)
			if err != nil {
				log.Printf("domain_server: Error verifying host att: %s\n", err)
				sendError(err, ms)
				continue
			}
			programKeyBytes := request.GetProgramKey()
			verifier, err := tao.UnmarshalKey(programKeyBytes)
			if err != nil {
				log.Printf("domain_server: Error parsing program key: %v\n", err)
				sendError(err, ms)
				continue
			}
			if !verifier.ToPrincipal().Identical(kPrin) {
				errStr := "domain_server: Program key in request does not match key being attested to."
				log.Println(errStr)
				sendError(errors.New(errStr), ms)
				continue
			}
			prog_is_trusted := false
			for _, trusted_prog := range trustedEntities.TrustedProgramTaoNames {
				if trusted_prog == prog.String() {
					prog_is_trusted = true
				}
			}
			if !prog_is_trusted {
				errStr := "domain_server: ProgramTaoName in request is not authorized to execute"
				log.Println(errStr)
				sendError(errors.New(errStr), ms)
				continue
			}
			log.Println("domain_server: attestation passes verification checks, creating program cert")
			cert, err := domain_service.GenerateProgramCert(domain, serialNumber, prog,
				verifier, time.Now(), time.Now().AddDate(1, 0, 0))
			if err != nil {
				log.Printf("domain_server: Error generating program cert: %s\n", err)
				sendError(err, ms)
				continue
			}
			resp := &domain_service.DomainServiceResponse{
				DerProgramCert: cert.Raw}
			log.Println("domain_server: program cert created. Sending response back to program.")
			if _, err := ms.WriteMessage(resp); err != nil {
				log.Printf("domain_server: Error sending cert on the channel: %s\n ",
					err)
				continue
			}
		case domain_service.DomainServiceRequest_MANAGE_POLICY:
			// TODO(sidtelang)
		case domain_service.DomainServiceRequest_REVOKE_CERTIFICATE:
			revokedCertificates, err = domain_service.RevokeCertificate(
				request.GetSerializedPolicyAttestation(), revokedCertificates, domain)
			if err != nil {
				log.Printf("domain_server: Error revoking certificate: %s\n", err)
			}
			sendError(err, ms)
		case domain_service.DomainServiceRequest_GET_CRL:
			nowTime := time.Now()
			expireTime := time.Now().AddDate(1, 0, 0)
			crl, err := domain.Keys.SigningKey.CreateCRL(domain.Keys.Cert,
				revokedCertificates, nowTime, expireTime)
			resp := domain_service.DomainServiceResponse{}
			if err != nil {
				errStr := err.Error()
				resp.ErrorMessage = &errStr
			} else {
				resp.Crl = crl
			}
			if _, err := ms.WriteMessage(&resp); err != nil {
				log.Printf("domain_server: Error sending response on the channel: %s\n ", err)
			}
		}
	}
}

func sendError(err error, ms *util.MessageStream) {
	var errStr = ""
	if err != nil {
		errStr = err.Error()
	}
	resp := &domain_service.DomainServiceResponse{ErrorMessage: &errStr}
	if _, err := ms.WriteMessage(resp); err != nil {
		log.Printf("domain_server: Error sending resp on the channel: %s\n ", err)
	}
}
