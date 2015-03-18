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
	"fmt"
	"net"
	"os"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

// HandleCARequest checks a request from a program and responds with a truncated
// delegation signed by the policy key.
func HandleCARequest(conn net.Conn, s *tao.Signer, guard tao.Guard) {
	defer conn.Close()

	// Expect an attestation from the client.
	ms := util.NewMessageStream(conn)
	var a tao.Attestation
	if err := ms.ReadMessage(&a); err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't read attestation from channel:", err)
		return
	}

	peerCert := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
	if err := ValidatePeerAttestation(&a, peerCert, guard); err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't validate peer attestation:", err)
		return
	}

	truncSays, pe, err := TruncateAttestation(s.ToPrincipal(), &a)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't truncate the attestation:", err)
		return
	}

	// TODO(tmroeder): fix this to check the time and make sure we're not
	// signing an unbounded attestation to this program.
	ra, err := tao.GenerateAttestation(s, nil, truncSays)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't attest to the new says statement:", err)
		return
	}

	// Add an endorsement to this PrinExt Program hash so the receiver can check
	// it successfully against policy.
	endorsement := auth.Says{
		Speaker: s.ToPrincipal(),
		Message: auth.Pred{
			Name: "TrustedProgramHash",
			Arg:  []auth.Term{auth.PrinTail{Ext: []auth.PrinExt{pe}}},
		},
	}
	if truncSays.Time != nil {
		i := *truncSays.Time
		endorsement.Time = &i
	}
	if truncSays.Expiration != nil {
		i := *truncSays.Expiration
		endorsement.Expiration = &i
	}
	ea, err := tao.GenerateAttestation(s, nil, endorsement)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't generate an endorsement for this program:", err)
		return
	}
	eab, err := proto.Marshal(ea)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't marshal an endorsement:", err)
		return
	}
	ra.SerializedEndorsements = [][]byte{eab}

	if _, err := ms.WriteMessage(ra); err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't return the attestation on the channel:", err)
		return
	}

	return
}

// RequestAttestation connects to a CA and gets an attestation back from it.
// This might be a truncated attestation (in which case, the right next step is
// to verify the truncated attesation, as in RequestTruncatedAttestation), or it
// might be some other kind of attestation (like a KeyNegoServer attestation,
// which provides a policy-key-signed X.509 certificate for the auth name of
// this program).
func RequestAttestation(network, addr string, keys *tao.Keys, v *tao.Verifier) (*tao.Attestation, error) {
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
	defer conn.Close()

	// Tao handshake: send client delegation.
	ms := util.NewMessageStream(conn)
	if _, err = ms.WriteMessage(keys.Delegation); err != nil {
		return nil, err
	}

	// Read the truncated attestation and check it.
	var a tao.Attestation
	if err := ms.ReadMessage(&a); err != nil {
		return nil, err
	}

	ok, err := v.Verify(a.SerializedStatement, tao.AttestationSigningContext, a.Signature)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("invalid attestation signature from Tao CA")
	}

	return &a, nil

}

// RequestTruncatedAttestation connects to a CA instance, sends the attestation
// for an X.509 certificate, and gets back a truncated attestation with a new
// principal name based on the policy key.
func RequestTruncatedAttestation(network, addr string, keys *tao.Keys, v *tao.Verifier) (*tao.Attestation, error) {
	a, err := RequestAttestation(network, addr, keys, v)
	if err != nil {
		return nil, err
	}

	truncStmt, err := auth.UnmarshalForm(a.SerializedStatement)
	if err != nil {
		return nil, err
	}

	says, _, err := TruncateAttestation(v.ToPrincipal(), keys.Delegation)
	if err != nil {
		return nil, err
	}

	if !IdenticalDelegations(says, truncStmt) {
		return nil, fmt.Errorf("the statement returned by the TaoCA was different than what we expected")
	}

	return a, nil
}
