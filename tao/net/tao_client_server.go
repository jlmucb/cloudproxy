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
	"errors"
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

func generateX509() (*tao.Keys, *tls.Certificate, error) {
	keys, err := tao.NewTemporaryTaoDelegatedKeys(tao.Signing, tao.Parent())
	if err != nil {
		return nil, nil, err
	}

	cert, err := keys.SigningKey.CreateSelfSignedX509(&pkix.Name{
		Organization: []string{"Google Tao Demo"}})
	if err != nil {
		return nil, nil, err
	}
	// TODO(kwalsh) keys should save cert on disk if keys are on disk
	keys.Cert = cert

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	keyBytes, err := tao.MarshalSignerDER(keys.SigningKey)
	if err != nil {
		return nil, nil, err
	}
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: keyBytes})

	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, nil, fmt.Errorf("can't parse cert: %s\n", err.Error())
	}

	return keys, &tlsCert, nil
}

func SetupTLSServer(serverAddr string) (net.Listener, error) {
	_, cert, err := generateX509()
	if err != nil {
		return nil, fmt.Errorf("server: can't create key and cert: %s\n", err.Error())
	}
	return tls.Listen("tcp", serverAddr, &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*cert},
		InsecureSkipVerify: true,
	})
}

func SetupTLSClient(serverAddr string) (net.Conn, *tao.Keys, error) {
	keys, cert, err := generateX509()
	if err != nil {
		return nil, nil, fmt.Errorf("client: can't create key and cert: %s\n", err.Error())
	}
	conn, err := tls.Dial("tcp", serverAddr, &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*cert},
		InsecureSkipVerify: true,
	})
	return conn, keys, err
}

// Tao mode client/server

func SetupTaoClient(serverAddr string) (net.Conn, error) {
	conn, keys, err := SetupTLSClient(serverAddr)
	if err != nil {
		return nil, err
	}

	// tao handshake: send our delegation
	ms := util.NewMessageStream(conn)
	_, err = ms.WriteMessage(keys.Delegation)
	if err != nil {
		return nil, err
	}

	// tao handshake: read peer delegation
	var a tao.Attestation
	err = ms.ReadMessage(&a)
	if err != nil {
		return nil, err
	}

	// check if peer delegation matches tls key
	peerCert := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
	// TODO(kwalsh) Verify peer key was checked by tls even though we set tls
	// config.InsecureSkipVerify. We don't care about the name or other
	// certificate details ata ll (hence config.InsecureSkipVerify), but we do
	// care that the key in the certificate is actually held by the peer.
	_ = peerCert

	// TODO(kwalsh)
	// * verify delegation is well formed and properly signed
	// * verify tls key matches the key delegated by this delegation
	// * get name from delegation, store somewhere (e.g. in conn, eventually)

	return conn, errors.New("not yet implemented")
}
