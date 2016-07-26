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
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-tpm/tpm"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/tpm2"
)

// ValidSigner checks the signature on an attestation and, if so, returns the
// principal name for the signer.
func (a *Attestation) ValidSigner() (auth.Prin, error) {
	signer := auth.NewPrin(*a.SignerType, a.SignerKey)
	switch *a.SignerType {
	case "tpm":
		// The PCRs are contained in the Speaker of an auth.Says statement that
		// makes up the a.SerializedStatement.
		f, err := auth.UnmarshalForm(a.SerializedStatement)
		if err != nil {
			return auth.Prin{}, newError("tao: couldn't unmarshal the statement: %s", err)
		}

		// A TPM attestation must be an auth.Says.
		says, ok := f.(auth.Says)
		if !ok {
			return auth.Prin{}, newError("tao: the attestation statement was not an auth.Says statement")
		}

		// Signer is tpm; use tpm-specific signature verification. Extract the
		// PCRs from the issuer name, unmarshal the key as an RSA key, and call
		// tpm.VerifyQuote().
		speaker, ok := says.Speaker.(auth.Prin)
		if !ok {
			return auth.Prin{}, newError("tao: the speaker of an attestation must be an auth.Prin")
		}
		pcrNums, pcrVals, err := extractPCRs(speaker)
		if err != nil {
			return auth.Prin{}, newError("tao: couldn't extract TPM PCRs from attestation: %s", err)
		}

		pk, err := extractTPMKey(a.SignerKey)
		if err != nil {
			return auth.Prin{}, newError("tao: couldn't extract TPM key from attestation: %s", err)
		}
		if err := tpm.VerifyQuote(pk, a.SerializedStatement, a.Signature, pcrNums, pcrVals); err != nil {
			return auth.Prin{}, newError("tao: TPM quote failed verification: %s", err)
		}

		return signer, nil
	case "tpm2":
		// TODO -- tpm2
		// The PCRs are contained in the Speaker of an auth.Says statement that
		// makes up the a.SerializedStatement.
		f, err := auth.UnmarshalForm(a.SerializedStatement)
		if err != nil {
			return auth.Prin{}, newError("tao: couldn't unmarshal the statement: %s", err)
		}

		// put this back in
		// A TPM attestation must be an auth.Says.
		says, ok := f.(auth.Says)
		if !ok {
			return auth.Prin{}, newError("tao: the attestation statement was not an auth.Says statement")
		}

		// Signer is tpm; use tpm-specific signature verification. Extract the
		// PCRs from the issuer name, unmarshal the key as an RSA key, and call
		// tpm2.VerifyQuote().
		speaker, ok := says.Speaker.(auth.Prin)
		if !ok {
			return auth.Prin{}, newError("tao: the speaker of an attestation must be an auth.Prin")
		}

		key, err := extractTPM2Key(a.SignerKey)
		if err != nil {
			return auth.Prin{}, newError("tao: couldn't extract TPM key from attestation: %s", err)
		}
		pcrNums, pcrVal, err := extractTpm2PCRs(speaker)
		if err != nil {
			return auth.Prin{}, newError("tao: couldn't extract TPM PCRs from attestation: %s", err)
		}

		ok, err = tpm2.VerifyTpm2Quote(a.SerializedStatement,
			pcrNums, pcrVal, a.Tpm2QuoteStructure, a.Signature,
			key)
		if err != nil {
			return auth.Prin{}, newError("tao: TPM quote verification error")
		}
		if !ok {
			return auth.Prin{}, newError("tao: TPM quote failed verification")
		}
		return signer, nil
	case "key":
		// Signer is ECDSA key, use Tao signature verification.
		v, err := UnmarshalKey(a.SignerKey)
		if err != nil {
			return auth.Prin{}, err
		}
		ok, err := v.Verify(a.SerializedStatement, AttestationSigningContext, a.Signature)
		if err != nil {
			return auth.Prin{}, err
		}
		if !ok {
			return auth.Prin{}, newError("tao: attestation signature invalid")
		}
		return signer, nil
	default:
		return auth.Prin{}, newError("tao: attestation signer principal unrecognized: %s", signer.String())
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
	var stmt *auth.Says
	if ptr, ok := f.(*auth.Says); ok {
		stmt = ptr
	} else if val, ok := f.(auth.Says); ok {
		stmt = &val
	} else {
		return auth.Says{}, newError("tao: attestation statement has wrong type: %T", f)
	}
	if a.SerializedDelegation == nil {
		// Case (1), no delegation present.
		// Require that stmt.Speaker be a subprincipal of (or identical to) a.signer.
		if !auth.SubprinOrIdentical(stmt.Speaker, signer) {
			return auth.Says{}, newError("tao: attestation statement signer (%v) does not evidently speak for issuer (%v)", signer, stmt.Speaker)
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
		var delegation *auth.Speaksfor
		if ptr, ok := delegationStatement.Message.(*auth.Speaksfor); ok {
			delegation = ptr
		} else if val, ok := delegationStatement.Message.(auth.Speaksfor); ok {
			delegation = &val
		} else {
			return auth.Says{}, newError("tao: attestation delegation is wrong type")
		}
		if !delegationStatement.Speaker.Identical(delegation.Delegator) {
			return auth.Says{}, newError("tao: attestation delegation is invalid")
		}
		if !auth.SubprinOrIdentical(delegation.Delegate, signer) {
			return auth.Says{}, newError("tao: attestation delegation irrelevant to signer")
		}
		if !auth.SubprinOrIdentical(stmt.Speaker, delegation.Delegator) {
			return auth.Says{}, newError("tao: attestation delegation irrelevant to issuer")
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
	return *stmt, nil
}

// GenerateAttestation uses the signing key to generate an attestation for this
// statement.
func GenerateAttestation(s *Signer, delegation []byte, stmt auth.Says) (*Attestation, error) {
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
		SignerType:          proto.String("key"),
		SignerKey:           s.GetVerifier().MarshalKey(),
	}

	if len(delegation) > 0 {
		a.SerializedDelegation = delegation
	}

	return a, nil
}
