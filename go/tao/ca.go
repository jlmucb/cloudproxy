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
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

var errVerifyFailed = errors.New("CARequest: invalid signature")
var errInvalidResponse = errors.New("CARequest: unexpected response")

// HandleCARequest checks a request from a program and responds with a truncated
// delegation signed by the policy key.
func HandleCARequest(conn net.Conn, s *Signer, guard Guard) {
	defer conn.Close() // TODO(cjpatton) This should be managed by calling function.

	// Get request.
	ms := util.NewMessageStream(conn)
	var req CARequest
	if err := ms.ReadMessage(&req); err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't read from channel:", err)
		return
	}

	resp := respond(&req, s, guard)

	if _, err := ms.WriteMessage(resp); err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't write to the channel:", err)
	}
}

// Create a response to a request.
func respond(req *CARequest, s *Signer, guard Guard) (resp *CAResponse) {
	resp = new(CAResponse)
	resp.Type = CAType_ERROR.Enum()

	if *req.Type == CAType_ATTESTATION && req.Attestation != nil {
		truncSays, pe, err := TruncateAttestation(s.ToPrincipal(), req.Attestation)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Couldn't truncate the attestation:", err)
			return
		}

		// TODO(tmroeder): fix this to check the time and make sure we're not
		// signing an unbounded attestation to this program.
		ra, err := GenerateAttestation(s, nil, truncSays)
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
		ea, err := GenerateAttestation(s, nil, endorsement)
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

		resp.Type = CAType_ATTESTATION.Enum()
		resp.Attestation = ra

	} else if *req.Type == CAType_DATALOG_POLICY {
		dg, ok := guard.(*DatalogGuard)
		if !ok {
			fmt.Fprintln(os.Stderr, "Requested wrong type")
			return
		}

		sdb, err := dg.GetSignedDatalogRules(s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Couldn't get signed datalog rules: %s", err)
			return
		}

		resp.Type = CAType_DATALOG_POLICY.Enum()
		resp.SignedDatalogRules = sdb

	} else if *req.Type == CAType_ACL_POLICY {
		ac, ok := guard.(*ACLGuard)
		if !ok {
			fmt.Fprintln(os.Stderr, "Requested wrong type")
			return
		}

		sdb, err := ac.GetSignedACLSet(s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Couldn't get signed ACL set: %s", err)
			return
		}
		resp.Type = CAType_ACL_POLICY.Enum()
		resp.SignedAclSet = sdb

	} else {
		resp.Type = CAType_UNDEFINED.Enum()
	}

	return
}

// RequestAttestation connects to a CA and gets an attestation back from it.
// This might be a truncated attestation (in which case, the right next step is
// to verify the truncated attesation, as in RequestTruncatedAttestation), or it
// might be some other kind of attestation (like a KeyNegoServer attestation,
// which provides a policy-key-signed X.509 certificate for the auth name of
// this program).
func RequestAttestation(network, addr string, keys *Keys, v *Verifier) (*Attestation, error) {

	// Establish connection wtih the CA.
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Create a CARequest.
	req := &CARequest{
		Type:        CAType_ATTESTATION.Enum(),
		Attestation: keys.Delegation,
	}

	// Tao handshake: send client delegation.
	ms := util.NewMessageStream(conn)
	if _, err = ms.WriteMessage(req); err != nil {
		return nil, err
	}

	// Read the truncated attestation and check it.
	var resp CAResponse
	if err := ms.ReadMessage(&resp); err != nil {
		return nil, err
	}

	ok, err := v.Verify(resp.Attestation.SerializedStatement,
		AttestationSigningContext, resp.Attestation.Signature)
	if !ok {
		return nil, errVerifyFailed
	} else if err != nil {
		return nil, err
	}

	if *resp.Type != CAType_ATTESTATION {
		return nil, errInvalidResponse
	}

	return resp.Attestation, nil
}

// RequestTruncatedAttestation connects to a CA instance, sends the attestation
// for an X.509 certificate, and gets back a truncated attestation with a new
// principal name based on the policy key.
func RequestTruncatedAttestation(network, addr string, keys *Keys, v *Verifier) (*Attestation, error) {
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

// RequestDatalogRules requests the policy from a TaoCA running a DatalogGuard.
// Verify the signature with the public policy key `v`.
func RequestDatalogRules(network, addr string, v *Verifier) (*DatalogRules, error) {

	// Establish connection wtih the CA.
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Create a CArequest.
	req := &CARequest{
		Type: CAType_DATALOG_POLICY.Enum(),
	}

	// Send request.
	ms := util.NewMessageStream(conn)
	if _, err = ms.WriteMessage(req); err != nil {
		return nil, err
	}

	// Receive response.
	var resp CAResponse
	if err := ms.ReadMessage(&resp); err != nil {
		return nil, err
	}

	// Verify signature.
	ok, err := v.Verify(resp.SignedDatalogRules.SerializedRules,
		DatalogRulesSigningContext, resp.SignedDatalogRules.Signature)
	if !ok {
		return nil, errVerifyFailed
	} else if err != nil {
		return nil, err
	}

	if *resp.Type != CAType_DATALOG_POLICY {
		return nil, errInvalidResponse
	}

	var db DatalogRules
	if err := proto.Unmarshal(resp.SignedDatalogRules.SerializedRules, &db); err != nil {
		return nil, err
	}

	return &db, nil
}

// RequestACLSet requests the policy from a TaoCA running an ACLGuard. Verify
// the signature with the public policy key `v`.
func RequestACLSet(network, addr string, v *Verifier) (*ACLSet, error) {

	// Establish connection wtih the CA.
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Create a CArequest.
	req := &CARequest{
		Type: CAType_ACL_POLICY.Enum(),
	}

	// Send request.
	ms := util.NewMessageStream(conn)
	if _, err = ms.WriteMessage(req); err != nil {
		return nil, err
	}

	// Receive response.
	var resp CAResponse
	if err := ms.ReadMessage(&resp); err != nil {
		return nil, err
	}

	// Verify signature.
	ok, err := v.Verify(resp.SignedAclSet.SerializedAclset,
		ACLGuardSigningContext, resp.SignedAclSet.Signature)
	if !ok {
		return nil, errVerifyFailed
	} else if err != nil {
		return nil, err
	}

	if *resp.Type != CAType_ACL_POLICY {
		return nil, errInvalidResponse
	}

	var db ACLSet
	if err := proto.Unmarshal(resp.SignedAclSet.SerializedAclset, &db); err != nil {
		return nil, err
	}

	return &db, nil
}
