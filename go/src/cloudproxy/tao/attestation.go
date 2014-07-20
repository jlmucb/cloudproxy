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
	"errors"
	"fmt"

	"code.google.com/p/goprotobuf/proto"

	"cloudproxy/tao/auth"
)

// ValidSigner checks the signature on an attestation and, if so, returns the signer.
func (a *Attestation) ValidSigner() (*auth.Prin, error) {
	signer, err := auth.NewPrin(*a.Signer)
	if err != nil {
		return nil, err
	}
	if len(signer.Part) != 1 {
		return nil, fmt.Errorf("tao: attestation signer principal malformed: %s", *a.Signer)
	}
	if signer.Part[0].Name == "TPM" {
		// Signer is tpm, use tpm-specific signature verification.
		return nil, errors.New("tpm signature verification not yet implemented")
	} else if signer.Part[0].Name == "Key" {
		// Signer is ECDSA key, use Tao signature verification.
		v, err := FromPrincipalName(signer.String())
		if err != nil {
			return nil, err
		}
		if ok, err := v.Verify(a.SerializedStatement, AttestationSigningContext, a.Signature); !ok {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("tao: attestation signer principal unrecognized: %s", signer.String())
	}
	return signer, nil
}

// Validate checks whether an attestation is valid and, if so, it returns the
// statement conveyed by the attestation.
func (a *Attestation) Validate() (*Statement, error) {
	signer, err := a.ValidSigner()
	if err != nil {
		return nil, err
	}
	var stmt Statement
	if err = proto.Unmarshal(a.SerializedStatement, &stmt); err != nil {
		return nil, err
	}
	issuer, err := auth.NewPrin(*stmt.Issuer)
	if err != nil {
		return nil, fmt.Errorf("tao: attestation statement issuer unrecognized: %s", *stmt.Issuer)
	}
	if a.SerializedDelegation == nil {
		// Case (1), no delegation present.
		// Require that s.issuer be a subprincipal of (or identical to) a.signer.
		if !auth.SubprinOrIdentical(issuer, signer) {
			return nil, fmt.Errorf("tao: attestation statement signer does not evidently speak for issuer")
		}
	} else {
		// Case (2), delegation present.
		// Require that:
		// - delegation conveys delegate speaksfor issuer0,
		// - a.signer speaks for delegate
		// - and issuer0 speaks for s.issuer
		var da Attestation
		if err := proto.Unmarshal(a.SerializedDelegation, &da); err != nil {
			return nil, err
		}
		delegation, err := da.Validate()
		if err != nil {
			return nil, err
		}
		if delegation.Delegate == nil {
			return nil, fmt.Errorf("tao: attestation delegation invalid")
		}
		delegate, err := auth.NewPrin(*delegation.Delegate)
		if err != nil {
			return nil, fmt.Errorf("tao: attestation delegation delegate invalid: %s", *delegation.Delegate)
		}
		issuer0, err := auth.NewPrin(*delegation.Issuer)
		if err != nil {
			return nil, fmt.Errorf("tao: attestation delegation issuer invalid: %s", *delegation.Issuer)
		}
		if !auth.SubprinOrIdentical(delegate, signer) {
			return nil, fmt.Errorf("tao: attestation delegation irrelevant to signer")
		}
		if !auth.SubprinOrIdentical(issuer, issuer0) {
			return nil, fmt.Errorf("tao: attestation delegation irrelevant to issuer")
		}
		if *stmt.Time < *delegation.Time {
			*stmt.Time = *delegation.Time
		}
		if *stmt.Expiration > *delegation.Expiration {
			*stmt.Expiration = *delegation.Expiration
		}
	}
	return &stmt, nil
}
