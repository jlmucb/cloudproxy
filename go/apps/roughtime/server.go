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

// this is an adapted version of the server code in the roughtime
// for cloudproxy. this version uses Tao to listen and answer the queries.
package roughtime

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/jlmucb/cloudproxy/go/apps/roughtime/agl_roughtime/config"
	"github.com/jlmucb/cloudproxy/go/apps/roughtime/agl_roughtime/protocol"
	"github.com/jlmucb/cloudproxy/go/tao"

	"golang.org/x/crypto/ed25519"
)

type Server struct {
	keys       *tao.Keys // Various keys for this hosted program.
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	domain     *tao.Domain  // Policy guard and public key.
	listener   net.Listener // Socket where server listens for proxies/routers
}

func NewServer(path, network string, port int, x509Identity *pkix.Name, t tao.Tao) (*Server, error) {
	// Generate keys and get attestation from parent.
	keys, err := tao.NewTemporaryTaoDelegatedKeys(tao.Signing|tao.Crypting, t)
	if err != nil {
		return nil, err
	}

	// Create a certificate.
	pkInt := tao.PublicKeyAlgFromSignerAlg(*keys.SigningKey.Header.KeyType)
	sigInt := tao.SignatureAlgFromSignerAlg(*keys.SigningKey.Header.KeyType)
	keys.Cert, err = keys.SigningKey.CreateSelfSignedX509(pkInt, sigInt, int64(1),
		x509Identity)
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

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*cert},
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequestClientCert,
	}

	listener, err := tao.ListenAnonymous(network, fmt.Sprintf(":%d", port), tlsConfig,
		domain.Guard, domain.Keys.VerifyingKey, keys.Delegation)
	if err != nil {
		return nil, err
	}

	s := &Server{
		keys:       keys,
		publicKey:  pub,
		privateKey: priv,
		domain:     domain,
		listener:   listener,
	}

	return s, nil
}

func (s *Server) ServeForever() error {
	onlinePublicKey, onlinePrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("Cannot generate private key: " + err.Error())
	}

	// As this is just an example, the certificate is created covering the
	// maximum possible range.
	cert, err := protocol.CreateCertificate(0, ^uint64(0), onlinePublicKey, s.privateKey)
	if err != nil {
		return errors.New("Cannot generate certificate: " + err.Error())
	}

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
