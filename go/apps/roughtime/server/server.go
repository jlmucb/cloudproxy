// Copyright (c) 2016, Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// this is an adapted version of the server code in the roughtime for cloudproxy
// biggest difference is probably the listening
package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/jlmucb/cloudproxy/go/tao"

	"golang.org/x/crypto/ed25519"
	"roughtime.googlesource.com/go/config"
	"roughtime.googlesource.com/go/protocol"
)

var (
	port       = flag.Int("port", 5333, "Port number to listen on")
	configPath = flag.String("config", "tao.config", "Path to domain configuration file.")
)

// x509 identity of the mixnet router.
var x509Identity pkix.Name = pkix.Name{
	Organization:       []string{"Google Inc."},
	OrganizationalUnit: []string{"Cloud Security"},
}

type Server struct {
	keys     *tao.Keys    // Signing keys of this hosted program.
	domain   *tao.Domain  // Policy guard and public key.
	listener net.Listener // Socket where server listens for proxies/routers
}

func NewServer(path, network string, port int, x509Identity *pkix.Name, t tao.Tao) (*Server, error) {
	// Generate keys and get attestation from parent.
	keys, err := tao.NewTemporaryTaoDelegatedKeys(tao.Signing|tao.Crypting, t)
	if err != nil {
		return nil, err
	}

	// Create a certificate.
	keys.Cert, err = keys.SigningKey.CreateSelfSignedX509(x509Identity)
	if err != nil {
		return nil, err
	}

	// Load domain from local configuration.
	domain, err := tao.LoadDomain(path, nil)
	if err != nil {
		return nil, err
	}

	// Encode TLS certificate.
	cert, err := tao.EncodeTLSCert(keys)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*cert},
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequestClientCert,
	}

	listener, err := tao.Listen(network, fmt.Sprintf(":%d", port), tlsConfig,
		domain.Guard, domain.Keys.VerifyingKey, keys.Delegation)
	if err != nil {
		return nil, err
	}

	s := &Server{
		keys:     keys,
		domain:   domain,
		listener: listener,
	}

	return s, nil
}

func (s *Server) serveForever() error {
	onlinePublicKey, onlinePrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("Cannot generate private key: " + err.Error())
	}

	// As this is just an example, the certificate is created covering the
	// maximum possible range.
	cert, err := protocol.CreateCertificate(0, ^uint64(0), onlinePublicKey, (*s.keys.SigningKey).GetSigner().D.Bytes())
	if err != nil {
		return errors.New("Cannot generate certificate: " + err.Error())
	}

	log.Printf("Processing requests on port %d", *port)

	var packetBuf [protocol.MinRequestSize]byte

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Fatal(err)
		}

		n, err := conn.Read(packetBuf[:])
		if err != nil {
			log.Print(err)
		}

		if n < protocol.MinRequestSize {
			continue
		}

		packet, err := protocol.Decode(packetBuf[:n])
		if err != nil {
			continue
		}

		nonce, ok := packet[protocol.TagNonce]
		if !ok || len(nonce) != protocol.NonceSize {
			continue
		}

		midpoint := uint64(time.Now().UnixNano() / 1000)
		radius := uint32(1000000)

		replies, err := protocol.CreateReplies([][]byte{nonce}, midpoint, radius, cert, onlinePrivateKey)
		if err != nil {
			log.Print(err)
			continue
		}

		if len(replies) != 1 {
			continue
		}

		conn.Write(replies[0])
	}
}

func generateKeyPair() error {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	fmt.Printf("Private key: %x\n\n", rootPrivate)

	exampleConfig := config.ServersJSON{
		Servers: []config.Server{
			config.Server{
				Name:          "FIXME",
				PublicKeyType: "ed25519",
				PublicKey:     rootPublic,
				Addresses: []config.ServerAddress{
					config.ServerAddress{
						Protocol: "udp",
						Address:  "FIXME",
					},
				},
			},
		},
	}

	jsonBytes, err := json.MarshalIndent(exampleConfig, "", "  ")
	if err != nil {
		return err
	}

	os.Stdout.Write(jsonBytes)
	os.Stdout.WriteString("\n")

	return nil
}

func main() {
	flag.Parse()

	s, err := NewServer(*configPath, "tcp", *port,
		&x509Identity, tao.Parent())
	if err != nil {
		log.Fatal(err)
	}
	err = s.serveForever()
	if err != nil {
		log.Fatal(err)
	}
}
