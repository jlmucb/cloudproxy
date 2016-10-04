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

package mixnet

import (
	"crypto/tls"
	"net"

	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util"
)

type routerListener struct {
	net.Listener
	guard      tao.Guard
	verifier   *tao.Verifier
	delegation *tao.Attestation
}

func Listen(network, laddr string, config *tls.Config, g tao.Guard, v *tao.Verifier, del *tao.Attestation) (net.Listener, error) {
	config.ClientAuth = tls.RequestClientCert
	inner, err := tls.Listen(network, laddr, config)
	if err != nil {
		return nil, err
	}

	return &routerListener{inner, g, v, del}, nil
}

func (l *routerListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Tao handshake Protocol:
	// 0. TLS handshake explicit handshake (so we can check cert first)
	// 1. Client -> Server: Tao delegation for X.509 certificate.
	// 2. Server: checks for a Tao-authorized program.
	// 3. Server -> Client: Tao delegation for X.509 certificate.
	// 4. Client: checks for a Tao-authorized program.
	err = c.(*tls.Conn).Handshake()
	if err != nil {
		return nil, err
	}

	ms := util.NewMessageStream(c)
	var a tao.Attestation
	if len(c.(*tls.Conn).ConnectionState().PeerCertificates) > 0 {
		if err := ms.ReadMessage(&a); err != nil {
			c.Close()
			return nil, err
		}

		if err := tao.AddEndorsements(l.guard, &a, l.verifier); err != nil {
			return nil, err
		}

		peerCert := c.(*tls.Conn).ConnectionState().PeerCertificates[0]
		if err := tao.ValidatePeerAttestation(&a, peerCert, l.guard); err != nil {
			c.Close()
			return nil, err
		}
	}
	if _, err := ms.WriteMessage(l.delegation); err != nil {
		c.Close()
		return nil, err
	}

	return c, nil
}
