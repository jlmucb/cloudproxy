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

package net

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"

	"github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	"github.com/jlmucb/cloudproxy/util"
)

// A Listener implements net.Listener for Tao connections. Each time it accepts
// a connection, it exchanges Tao attestation chains and checks the attestation
// for the certificate of the client against its tao.Guard. The guard in this
// case should be the guard of the Tao domain. This listener allows connections
// from any program that is authorized under the Tao to execute.
type listener struct {
	gl         net.Listener
	guard      tao.Guard
	delegation *tao.Attestation
}

// NewTaoListener returns a new Tao-based net.Listener that uses the underlying
// crypto/tls net.Listener and a tao.Guard to check whether or not connections
// are authorized.
func Listen(network, laddr string, config *tls.Config, g tao.Guard, del *tao.Attestation) (net.Listener, error) {
	config.ClientAuth = tls.RequireAnyClientCert
	inner, err := tls.Listen(network, laddr, config)
	if err != nil {
		return nil, err
	}
	return &listener{inner, g, del}, nil
}

// validatePeerAttestation checks a tao.Attestation for a given Listener against
// an X.509 certificate from a TLS channel.
func validatePeerAttestation(a *tao.Attestation, cert *x509.Certificate, guard tao.Guard) error {
	stmt, err := a.Validate()
	if err != nil {
		return err
	}

	// Insist that the message of the statement be a SpeaksFor and that the
	// initial term be an auth.Prin of type key. Note that Validate has already
	// checked the expirations and the times and the general well-formedness of
	// the attestation.
	sf, ok := stmt.Message.(auth.Speaksfor)
	if !ok {
		return errors.New("a peer attestation must have an auth.Speaksfor as a message")
	}

	// This key must contain the serialized X.509 certificate.
	kprin, ok := sf.Delegate.(auth.Prin)
	if !ok {
		return errors.New("a peer attestation must have an auth.Prin as its delegate")
	}

	if kprin.Type != "key" {
		return errors.New("a peer attestation must have an auth.Prin of type 'key' as its delegate")
	}

	if _, ok := kprin.Key.(auth.Bytes); !ok {
		return errors.New("a peer attestation must have a Key of type auth.Bytes")
	}

	prin, ok := sf.Delegator.(auth.Prin)
	if !ok {
		return errors.New("a peer attestation must have an auth.Prin as its delegator")
	}

	// Ask the Tao Domain if this program is allowed to execute.
	// TODO(tmroeder): the current implementation assumes that the Tao Guard is
	// already able to check authorization of Execute for both programs. In
	// general, this might not be true.
	if !guard.IsAuthorized(prin, "Execute", nil) {
		return errors.New("a principal delegator in a client attestation must be authorized to Execute")
	}

	// The bytes of the delegate are the result of ToPrincipal on
	// tao.Keys.SigningKey. Check that this represents the same key as the one
	// in the certificate.
	verifier, err := tao.FromPrincipal(kprin)
	if err != nil {
		return err
	}
	if !verifier.Equals(cert) {
		return errors.New("a peer attestation must have an auth.Prin.Key of type auth.Bytes where the bytes match the auth.Prin representation of the X.509 certificate.")
	}

	return nil
}

// Accept waits for a connect, accepts it using the underlying Conn and checks
// the attestations and the statement.
func (l *listener) Accept() (net.Conn, error) {
	c, err := l.gl.Accept()
	if err != nil {
		return nil, err
	}

	// Protocol:
	// 0. TLS handshake (executed automatically on first message)
	// 1. Client -> Server: Tao delegation for X.509 certificate.
	// 2. Server: checks for a Tao-authorized program.
	// 3. Server -> Client: Tao delegation for X.509 certificate.
	// 4. Client: checks for a Tao-authorized program.
	ms := util.NewMessageStream(c)
	var a tao.Attestation
	if err := ms.ReadMessage(&a); err != nil {
		c.Close()
		return nil, err
	}

	peerCert := c.(*tls.Conn).ConnectionState().PeerCertificates[0]
	if err := validatePeerAttestation(&a, peerCert, l.guard); err != nil {
		c.Close()
		return nil, err
	}

	if _, err := ms.WriteMessage(l.delegation); err != nil {
		c.Close()
		return nil, err
	}

	return c, nil
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
// This implementation passes the Close operation down to its inner listener.
func (l *listener) Close() error {
	return l.gl.Close()
}

// Addr returns the listener's network address.
func (l *listener) Addr() net.Addr {
	return l.gl.Addr()
}
