// Copyright (c) 2014, Google, Inc. All rights reserved.
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

// Package net provides Tao-specific networking functions and types.
package net

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"time"

	"github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/util"
)

// TLS mode client/server

const (
	x509duration = 24 * time.Hour
	x509keySize  = 2048
)

// EncodeTLSCert combines a signing key and a certificate in a single tls
// certificate suitable for a TLS config.
func EncodeTLSCert(keys *tao.Keys) (*tls.Certificate, error) {
	if keys.Cert == nil {
		return nil, fmt.Errorf("client: can't encode a nil certificate")
	}
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: keys.Cert.Raw})
	keyBytes, err := tao.MarshalSignerDER(keys.SigningKey)
	if err != nil {
		return nil, err
	}
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: keyBytes})

	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, fmt.Errorf("can't parse cert: %s\n", err.Error())
	}

	return &tlsCert, nil
}

// generateX509 creates a fresh set of Tao-delegated keys and gets a certificate
// from these keys.
func generateX509() (*tao.Keys, *tls.Certificate, error) {
	keys, err := tao.NewTemporaryTaoDelegatedKeys(tao.Signing, tao.Parent())
	if err != nil {
		return nil, nil, err
	}

	// TODO(tmroeder): fix the name
	cert, err := keys.SigningKey.CreateSelfSignedX509(&pkix.Name{
		Organization: []string{"Google Tao Demo"}})
	if err != nil {
		return nil, nil, err
	}
	// TODO(kwalsh) keys should save cert on disk if keys are on disk
	keys.Cert = cert
	tc, err := EncodeTLSCert(keys)
	return keys, tc, err
}

// ListenTLS creates a fresh certificate and listens for TLS connections using
// it.
func ListenTLS(network, addr string) (net.Listener, error) {
	_, cert, err := generateX509()
	if err != nil {
		return nil, fmt.Errorf("server: can't create key and cert: %s\n", err.Error())
	}
	return tls.Listen(network, addr, &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*cert},
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
	})
}

// DialTLS creates a new X.509 certs from fresh keys and dials a given TLS
// address.
func DialTLS(network, addr string) (net.Conn, *tao.Keys, error) {
	keys, cert, err := generateX509()
	if err != nil {
		return nil, nil, fmt.Errorf("client: can't create key and cert: %s\n", err.Error())
	}
	conn, err := tls.Dial(network, addr, &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*cert},
		InsecureSkipVerify: true,
	})
	return conn, keys, err
}

// Dial connects to a Tao TLS server, performs a TLS handshake, and exchanges
// tao.Attestation values with the server, checking that this is a Tao server
// that is authorized to Execute. It uses a Tao Guard to perform this check.
func Dial(network, addr string, guard tao.Guard) (net.Conn, error) {
	keys, _, err := generateX509()
	if err != nil {
		return nil, fmt.Errorf("client: can't create key and cert: %s\n", err.Error())
	}

	return DialWithKeys(network, addr, guard, keys)
}

// DialWithKeys connects to a Tao TLS server using an existing set of keys.
func DialWithKeys(network, addr string, guard tao.Guard, keys *tao.Keys) (net.Conn, error) {
	if keys.Cert == nil {
		return nil, fmt.Errorf("client: can't dial with an empty client certificate\n")
	}
	tlsCert, err := EncodeTLSCert(keys)
	if err != nil {
		return nil, err
	}
	conn, err := tls.Dial(network, addr, &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*tlsCert},
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}

	// Tao handshake: send client delegation.
	ms := util.NewMessageStream(conn)
	if _, err = ms.WriteMessage(keys.Delegation); err != nil {
		conn.Close()
		return nil, err
	}

	// Tao handshake: read server delegation.
	var a tao.Attestation
	if err := ms.ReadMessage(&a); err != nil {
		conn.Close()
		return nil, err
	}

	// Validate the peer certificate according to the guard.
	peerCert := conn.ConnectionState().PeerCertificates[0]
	if err := validatePeerAttestation(&a, peerCert, guard); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}
