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
func (a *Attestation) ValidSigner() (signer auth.Prin, err error) {
	p, err := auth.UnmarshalPrin(*a.Signer)
	if err != nil {
		return
	}
	if len(signer.Ext) != 0 {
		err = fmt.Errorf("tao: attestation signer principal malformed: %s", signer)
		return
	}
	switch signer.Type {
	case "tpm":
		// Signer is tpm, use tpm-specific signature verification.
		// TODO(kwalsh) call tpm-specific verification code
		err = errors.New("tpm signature verification not yet implemented")
		return
	case "key":
		// Signer is ECDSA key, use Tao signature verification.
		v, err := FromPrincipal(signer)
		if err != nil {
			return
		}
		ok, err := v.Verify(a.SerializedStatement, AttestationSigningContext, a.Signature)
		if !ok {
			return
		}
		return p, nil
	default:
		err = fmt.Errorf("tao: attestation signer principal unrecognized: %s", signer.String())
		return
	}
}

// Validate checks whether an attestation is valid and, if so, it returns the
// statement conveyed by the attestation.
func (a *Attestation) Validate() (stmt auth.Says, err error) {
	signer, err := a.ValidSigner()
	if err != nil {
		return
	}
	f, err := auth.UnmarshalForm(a.SerializedStatement)
	if err != nil {
		return
	}
	msg, ok := f.(auth.Says)
	if !ok {
		err = fmt.Errof("tao: attestation statement has wrong type: %T", f)
		return
	}
	if a.SerializedDelegation == nil {
		// Case (1), no delegation present.
		// Require that msg.Speaker be a subprincipal of (or identical to) a.signer.
		if !auth.SubprinOrIdentical(msg.Speaker, signer) {
			err = fmt.Errorf("tao: attestation statement signer does not evidently speak for issuer")
			return
		}
	} else {
		// Case (2), delegation present.
		// Require that:
		// - delegation conveys delegator says delegate speaksfor delegator,
		// - a.signer speaks for delegate
		// - and delegator speaks for s.Speaker
		var da Attestation
		if err := proto.Unmarshal(a.SerializedDelegation, &da); err != nil {
			return
		}
		delegationStatement, err := da.Validate()
		if err != nil {
			return
		}
		delegation, ok := delegationStatement.Message.(Speaksfor)
		if !ok || !auth.Identical(delegationStatement.Speaker, delegation.Delegator) {
			err = fmt.Errorf("tao: attestation delegation is invalid")
			return
		}
		if !auth.SubprinOrIdentical(delegation.Delegate, signer) {
			return nil, fmt.Errorf("tao: attestation delegation irrelevant to signer")
		}
		if !auth.SubprinOrIdentical(msg.Speaker, delegation.Delegator) {
			return nil, fmt.Errorf("tao: attestation delegation irrelevant to issuer")
		}
		if msg.Time == nil {
			msg.Time = delegationStatement.Time
		} else if delegationStatement.Time != nil && *msg.Time < *delegationStatement.Time {
			msg.Time = delegationStatement.Time
		}
		if msg.Expiration == nil {
			msg.Expiration = delegation.Expiration
		} else if delegation.Expiration != nil && *msg.Expiration > *delegationStatement.Expiration {
			msg.Expiration = delegationStatement.Expiration
		}
	}
	stmt = msg
	return
}
