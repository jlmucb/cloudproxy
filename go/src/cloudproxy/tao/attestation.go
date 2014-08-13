// Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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
	"fmt"
	"time"

	"code.google.com/p/goprotobuf/proto"

	"cloudproxy/tao/auth"
)

// ValidSigner checks the signature on an attestation and, if so, returns the signer.
func (a *Attestation) ValidSigner() (auth.Prin, error) {
	signer, err := auth.UnmarshalPrin(a.Signer)
	if err != nil {
		return auth.Prin{}, err
	}
	if len(signer.Ext) != 0 {
		return auth.Prin{}, fmt.Errorf("tao: attestation signer principal malformed: %s", signer)
	}
	switch signer.Type {
	case "tpm":
		// Signer is tpm, use tpm-specific signature verification.
		// TODO(kwalsh) call tpm-specific verification code
		return auth.Prin{}, fmt.Errorf("tao: tpm signature verification not yet implemented")
	case "key":
		// Signer is ECDSA key, use Tao signature verification.
		v, err := FromPrincipal(signer)
		if err != nil {
			return auth.Prin{}, err
		}
		ok, err := v.Verify(a.SerializedStatement, AttestationSigningContext, a.Signature)
		if err != nil {
			return auth.Prin{}, err
		}
		if !ok {
			return auth.Prin{}, fmt.Errorf("tao: attestation signature invalid")
		}
		return signer, nil
	default:
		return auth.Prin{}, fmt.Errorf("tao: attestation signer principal unrecognized: %s", signer.String())
	}
}

// Validate checks whether an attestation is valid and, if so, it returns the
// statement conveyed by the attestation.
func (a *Attestation) Validate() (auth.Says, error) {
	signer, err := a.ValidSigner()
	if err != nil {
		return auth.Says{}, err
	}
	f, err := auth.UnmarshalForm(a.SerializedStatement)
	if err != nil {
		return auth.Says{}, err
	}
	stmt, ok := f.(auth.Says)
	if !ok {
		return auth.Says{}, fmt.Errorf("tao: attestation statement has wrong type: %T", f)
	}
	if a.SerializedDelegation == nil {
		// Case (1), no delegation present.
		// Require that stmt.Speaker be a subprincipal of (or identical to) a.signer.
		if !auth.SubprinOrIdentical(stmt.Speaker, signer) {
			return auth.Says{}, fmt.Errorf("tao: attestation statement signer does not evidently speak for issuer")
		}
	} else {
		// Case (2), delegation present.
		// Require that:
		// - delegation conveys delegator says delegate speaksfor delegator,
		// - a.signer speaks for delegate
		// - and delegator speaks for s.Speaker
		var da Attestation
		if err := proto.Unmarshal(a.SerializedDelegation, &da); err != nil {
			return auth.Says{}, err
		}
		delegationStatement, err := da.Validate()
		if err != nil {
			return auth.Says{}, err
		}
		delegation, ok := delegationStatement.Message.(auth.Speaksfor)
		if !ok || !delegationStatement.Speaker.Identical(delegation.Delegator) {
			return auth.Says{}, fmt.Errorf("tao: attestation delegation is invalid")
		}
		if !auth.SubprinOrIdentical(delegation.Delegate, signer) {
			return auth.Says{}, fmt.Errorf("tao: attestation delegation irrelevant to signer")
		}
		if !auth.SubprinOrIdentical(stmt.Speaker, delegation.Delegator) {
			return auth.Says{}, fmt.Errorf("tao: attestation delegation irrelevant to issuer")
		}
		if stmt.Time == nil {
			stmt.Time = delegationStatement.Time
		} else if delegationStatement.Time != nil && *stmt.Time < *delegationStatement.Time {
			stmt.Time = delegationStatement.Time
		}
		if stmt.Expiration == nil {
			stmt.Expiration = delegationStatement.Expiration
		} else if delegationStatement.Expiration != nil && *stmt.Expiration > *delegationStatement.Expiration {
			stmt.Expiration = delegationStatement.Expiration
		}
	}
	return stmt, nil
}

// GenerateAttestation uses the signing key to generate an attestation for this
// statement.
func GenerateAttestation(s *Signer, delegation []byte, stmt auth.Says) (*Attestation, error) {
	signer, err := s.ToPrincipal()
	if err != nil {
		return nil, err
	}

	t := time.Now()
	if stmt.Time == nil {
		i := t.UnixNano()
		stmt.Time = &i
	}

	if stmt.Expiration == nil {
		i := t.Add(365 * 24 * time.Hour).UnixNano()
		stmt.Expiration = &i
	}

	ser := auth.Marshal(stmt)

	sig, err := s.Sign(ser, AttestationSigningContext)
	if err != nil {
		return nil, err
	}

	a := &Attestation{
		SerializedStatement: ser,
		Signature:           sig,
		Signer:              auth.Marshal(signer),
	}

	if len(delegation) > 0 {
		a.SerializedDelegation = delegation
	}

	return a, nil
}

