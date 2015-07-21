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

package tao

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

// TLS mode client/server

const (
	x509duration = 24 * time.Hour
	x509keySize  = 2048
)

// EncodeTLSCert combines a signing key and a certificate in a single tls
// certificate suitable for a TLS config.
func EncodeTLSCert(keys *Keys) (*tls.Certificate, error) {
	if keys.Cert == nil {
		return nil, fmt.Errorf("client: can't encode a nil certificate")
	}
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: keys.Cert.Raw})
	keyBytes, err := MarshalSignerDER(keys.SigningKey)
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
func generateX509() (*Keys, *tls.Certificate, error) {
	keys, err := NewTemporaryTaoDelegatedKeys(Signing, Parent())
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
func DialTLS(network, addr string) (net.Conn, error) {
	keys, _, err := generateX509()
	if err != nil {
		return nil, fmt.Errorf("client: can't create key and cert: %s\n", err.Error())
	}

	return DialTLSWithKeys(network, addr, keys)
}

// DialTLSWithKeys connects to a TLS server using an existing set of keys.
func DialTLSWithKeys(network, addr string, keys *Keys) (net.Conn, error) {
	tlsCert, err := EncodeTLSCert(keys)
	conn, err := tls.Dial(network, addr, &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*tlsCert},
		InsecureSkipVerify: true,
	})
	return conn, err
}

// Dial connects to a Tao TLS server, performs a TLS handshake, and exchanges
// Attestation values with the server, checking that this is a Tao server
// that is authorized to Execute. It uses a Tao Guard to perform this check.
func DialWithNewX509(network, addr string, guard Guard, v *Verifier) (net.Conn, error) {
	keys, _, err := generateX509()
	if err != nil {
		return nil, fmt.Errorf("client: can't create key and cert: %s\n", err.Error())
	}

	return Dial(network, addr, guard, v, keys)
}

// Dial connects to a Tao TLS server, performs a TLS handshake, and verifies
// the Attestation value of the server, checking that the server is authorized
// to execute. If keys are provided (keys!=nil), then it sends an attestation
// of its identity to the peer.
func Dial(network, addr string, guard Guard, v *Verifier, keys *Keys) (net.Conn, error) {
	tlsConfig := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		InsecureSkipVerify: true,
	}

	// Set up certificate for two-way authentication.
	if keys != nil {
		if keys.Cert == nil {
			return nil, fmt.Errorf("client: can't dial with an empty client certificate\n")
		}
		tlsCert, err := EncodeTLSCert(keys)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{*tlsCert}
	}

	conn, err := tls.Dial(network, addr, tlsConfig)
	if err != nil {
		return nil, err
	}

	ms := util.NewMessageStream(conn)

	// Two-way Tao handshake: send client delegation.
	if keys != nil {
		if _, err = ms.WriteMessage(keys.Delegation); err != nil {
			conn.Close()
			return nil, err
		}
	}

	// Tao handshake: read server delegation.
	var a Attestation
	if err := ms.ReadMessage(&a); err != nil {
		conn.Close()
		return nil, err
	}

	if err := AddEndorsements(guard, &a, v); err != nil {
		conn.Close()
		return nil, err
	}

	// Validate the peer certificate according to the guard.
	peerCert := conn.ConnectionState().PeerCertificates[0]
	if err := ValidatePeerAttestation(&a, peerCert, guard); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// AddEndorsements reads the SerializedEndorsements in an attestation and adds
// the ones that are predicates signed by the policy key.
func AddEndorsements(guard Guard, a *Attestation, v *Verifier) error {
	// Before validating against the guard, check to see if there are any
	// predicates endorsed by the policy key. This allows truncated principals
	// to get the Tao CA to sign a statement of the form
	// TrustedHash(ext.Program(...)).
	for _, e := range a.SerializedEndorsements {
		var ea Attestation
		if err := proto.Unmarshal(e, &ea); err != nil {
			return err
		}

		f, err := auth.UnmarshalForm(ea.SerializedStatement)
		if err != nil {
			return err
		}

		says, ok := f.(auth.Says)
		if !ok {
			return fmt.Errorf("a serialized endorsement must be an auth.Says")
		}

		// TODO(tmroeder): check that this endorsement hasn't expired.
		pred, ok := says.Message.(auth.Pred)
		if !ok {
			return fmt.Errorf("the message in an endorsement must be a predicate")
		}

		signerPrin, err := auth.UnmarshalPrin(ea.Signer)
		if err != nil {
			return err
		}

		if !signerPrin.Identical(says.Speaker) {
			return fmt.Errorf("the speaker of an endorsement must be the signer")
		}
		if !v.ToPrincipal().Identical(signerPrin) {
			return fmt.Errorf("the signer of an endorsement must be the policy key")
		}
		if ok, err := v.Verify(ea.SerializedStatement, AttestationSigningContext, ea.Signature); (err != nil) || !ok {
			return fmt.Errorf("the signature on an endorsement didn't pass verification")
		}

		guard.AddRule(pred.String())
	}

	return nil
}

// TruncateAttestation cuts off a delegation chain at its "Program" subprincipal
// extension and replaces its prefix with the given key principal. It also
// returns the PrinExt that represents exactly the program hash.
func TruncateAttestation(kprin auth.Prin, a *Attestation) (auth.Says, auth.PrinExt, error) {
	// This attestation must have a top-level delegation to a key. Return an
	// authorization for this program rooted in the policy key. I don't like
	// this, since it seems like it's much riskier, since this doesn't say
	// anything about the context in which the program is running. Fortunately,
	// local policy rules: if a peer won't accept this cert, then the other
	// program will have to fall back on the longer attestation.
	stmt, err := auth.UnmarshalForm(a.SerializedStatement)
	if err != nil {
		return auth.Says{}, auth.PrinExt{}, err
	}

	says, ok := stmt.(auth.Says)
	if !ok {
		return auth.Says{}, auth.PrinExt{}, fmt.Errorf("the serialized statement must be a says")
	}
	// Replace the message with one that uses the new principal, taking the last
	// Program subprinicpal, and all its following elements. It should say:
	// policyKey.Program(...)... says key(...) speaksfor
	// policyKey.Program(...)..., signed policyKey.
	sf, ok := says.Message.(auth.Speaksfor)
	if !ok {
		return auth.Says{}, auth.PrinExt{}, fmt.Errorf("the message in the statement must be a speaksfor")
	}

	delegator, ok := sf.Delegator.(auth.Prin)
	if !ok {
		return auth.Says{}, auth.PrinExt{}, fmt.Errorf("the delegator must be a principal")
	}

	var prog auth.PrinExt
	found := false
	for _, sprin := range delegator.Ext {
		if !found && (sprin.Name == "Program") {
			found = true
			prog = sprin
		}

		if found {
			kprin.Ext = append(kprin.Ext, sprin)
		}
	}

	// TODO(tmroeder): make sure that the delegate is a key and is not, e.g.,
	// the policy key.
	truncSpeaksfor := auth.Speaksfor{
		Delegate:  sf.Delegate,
		Delegator: kprin,
	}
	truncSays := auth.Says{
		Speaker:    kprin,
		Time:       says.Time,
		Expiration: says.Expiration,
		Message:    truncSpeaksfor,
	}

	return truncSays, prog, nil
}

// IdenticalDelegations checks to see if two Form values are Says and are
// identical delegations (i.e., the Message must be an auth.Speaksfor).  This
// function is not in the auth package, since it's specific to a particular
// pattern.
func IdenticalDelegations(s, t auth.Form) bool {
	ss, ok := s.(auth.Says)
	if !ok {
		return false
	}
	st, ok := t.(auth.Says)
	if !ok {
		return false
	}
	if !ss.Speaker.Identical(st.Speaker) {
		return false
	}

	if (ss.Time == nil) != (st.Time == nil) {
		return false
	}
	if (ss.Time != nil) && (*ss.Time != *st.Time) {
		return false
	}
	if (ss.Expiration == nil) != (st.Expiration == nil) {
		return false
	}
	if (ss.Expiration != nil) && (*ss.Expiration != *st.Expiration) {
		return false
	}

	sfs, ok := ss.Message.(auth.Speaksfor)
	if !ok {
		return false
	}
	sft, ok := ss.Message.(auth.Speaksfor)
	if !ok {
		return false
	}

	if !sfs.Delegate.Identical(sft.Delegate) || !sfs.Delegator.Identical(sft.Delegator) {
		return false
	}

	return true
}
