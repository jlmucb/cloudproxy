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

// Package secret_disclosure contains functions which create, interpret and verify
// secret disclosure directives of the following form:
// 'policyKey says programName can read protectedObjectId'

package secret_disclosure

import (
	"bytes"
	"testing"

	"github.com/golang/protobuf/proto"
	po "github.com/jlmucb/cloudproxy/go/support_libraries/protected_objects"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

var ProgramName = auth.Prin{
	Type: "program",
	Key:  auth.Bytes([]byte(`fake program`)),
}

var ProtectedObjectName = "obj_name"
var ProtectedObjectEpoch = int32(0)
var ProtectedObjectId = po.ObjectIdMessage{
	ObjName:  &ProtectedObjectName,
	ObjEpoch: &ProtectedObjectEpoch,
}

func TestCreateDirective(t *testing.T) {
	policyKey, testDirective, err := generatePolicyKeyAndSignedDirective(Params{})
	if err != nil {
		t.Fatal("Error generating test directive and policy key.", err)
	}
	directive, err := CreateSecretDisclosureDirective(policyKey, &ProgramName, &ProtectedObjectId)
	if err != nil {
		t.Fatal("Error generating real directive.", err)
	}
	signatureValid, err := policyKey.SigningKey.GetVerifier().Verify(
		directive.SerializedStatement, SigningContext, directive.Signature)
	if err != nil {
		t.Fatal("Error verifying the signature")
	}
	if !signatureValid {
		t.Fatal("Signature on directive not valid")
	}
	if testDirective.GetType() != directive.GetType() ||
		!bytes.Equal(testDirective.GetSerializedStatement(), directive.GetSerializedStatement()) ||
		!bytes.Equal(testDirective.GetSigner(), directive.GetSigner()) {
		t.Fatal("Fields in directive do not match expected value")
	}
}

func TestVerifyDirective(t *testing.T) {
	policyKey, directive, err := generatePolicyKeyAndSignedDirective(Params{})
	if err != nil {
		t.Fatal("Error generating test directive and policy key.", err)
	}
	programName, protectedObjectId, err := VerifySecretDisclosureDirective(policyKey, directive)
	if err != nil {
		t.Fatal("Error verifying test directive", err)
	}
	if !ProgramName.Identical(programName) {
		t.Fatal("Verify returns different programName from expected value.")
	}
	if *protectedObjectId.ObjName != *ProtectedObjectId.ObjName ||
		*protectedObjectId.ObjEpoch != *ProtectedObjectId.ObjEpoch {
		t.Fatal("Verify returns different protectedObjectId from expected value.")
	}
}

func TestCreateAndVerifyDirective(t *testing.T) {
	policyKey, _, err := generatePolicyKeyAndSignedDirective(Params{})
	if err != nil {
		t.Fatal("Error generating test directive and policy key.", err)
	}
	directive, err := CreateSecretDisclosureDirective(policyKey, &ProgramName, &ProtectedObjectId)
	if err != nil {
		t.Fatal("Error when creating directive.", err)
	}
	programName, protectedObjectId, err := VerifySecretDisclosureDirective(policyKey, directive)
	if err != nil {
		t.Fatal("Error when verifying directive", err)
	}
	if !ProgramName.Identical(programName) {
		t.Fatal("Verify returns different programName from expected value.")
	}
	if *protectedObjectId.ObjName != *ProtectedObjectId.ObjName ||
		*protectedObjectId.ObjEpoch != *ProtectedObjectId.ObjEpoch {
		t.Fatal("Verify returns different protectedObjectId from expected value.")
	}
}

func TestVerifyDirectiveWithBadType(t *testing.T) {
	policyKey, testDirective, err := generatePolicyKeyAndSignedDirective(Params{})
	if err != nil {
		t.Fatal("Error generating test directive and policy key.", err)
	}
	testDirective.Type = nil
	programName, protectedObjectId, err := VerifySecretDisclosureDirective(
		policyKey, testDirective)
	if programName != nil ||
		protectedObjectId != nil ||
		err == nil {
		t.Fatal("Verify output is not an error")
	}
}

func TestVerifyDirectiveWithDifferentSignerAndPolicyKey(t *testing.T) {
	params := Params{
		Signer: []byte("Bad Signer"),
	}
	expectError(&params, t)
}

func TestVerifyDirectiveWithBadSignature(t *testing.T) {
	params := Params{
		Signature: []byte("Bad Signature"),
	}
	expectError(&params, t)
}

func TestVerifyDirectiveWithBadSays(t *testing.T) {
	params := Params{
		Says: auth.Const(true),
	}
	expectError(&params, t)
}

func TestVerifyDirectiveWithBadPredicate_badName(t *testing.T) {
	params := Params{
		CanRead: auth.Pred{
			Name: "CanNotRead",
		},
	}
	expectError(&params, t)
}

func TestVerifyDirectiveWithBadPredicate_badTerms(t *testing.T) {
	params := Params{
		CanRead: auth.Pred{
			Name: CanReadPredicate,
			Arg:  []auth.Term{auth.Int(0), auth.Str(""), auth.Str("a")},
			// TODO: Note make([]auth.Term, 3) above causes NPE in auth.Marshal(thisPred)
			// Is that a bug?
		},
	}
	expectError(&params, t)
}

func TestVerifyDirectiveWithBadProgramName(t *testing.T) {
	params := Params{
		ProgramName: auth.Str(""),
	}
	expectError(&params, t)
}

func TestVerifyDirectiveWithBadProtectedObjectId_invalidType(t *testing.T) {
	params := Params{
		SerializedObjectId: auth.Str(""),
	}
	expectError(&params, t)
}

func TestVerifyDirectiveWithBadProtectedObjectId_invalidProtoBuf(t *testing.T) {
	badBytes := []byte("bad bytes")
	params := Params{
		SerializedObjectId: auth.Bytes(badBytes),
	}
	expectError(&params, t)
}

func expectError(params *Params, t *testing.T) {
	policyKey, testDirective, err := generatePolicyKeyAndSignedDirective(*params)
	if err != nil {
		t.Fatal("Error generating test directive and policy key.", err)
	}
	testDirective.Type = nil
	programName, protectedObjectId, err := VerifySecretDisclosureDirective(
		policyKey, testDirective)
	if programName != nil ||
		protectedObjectId != nil ||
		err == nil {
		t.Fatal("Verify output is not an error")
	}
}

type Params struct {
	ProgramName        auth.Term
	SerializedObjectId auth.Term
	Says               auth.Form
	CanRead            auth.Form
	CanReadTerms       []auth.Term
	Signer             []byte
	Signature          []byte
	DirectiveType      *DirectiveMessageDirectiveType
}

func generatePolicyKeyAndSignedDirective(params Params) (*tao.Keys, *DirectiveMessage, error) {
	var programName auth.Term
	if params.ProgramName != nil {
		programName = params.ProgramName
	} else {
		programName = ProgramName
	}
	var serializedObjectId auth.Term
	if params.SerializedObjectId != nil {
		serializedObjectId = params.SerializedObjectId
	} else {
		bytes, err := proto.Marshal(&ProtectedObjectId)
		if err != nil {
			return nil, nil, err
		}
		serializedObjectId = auth.Bytes(bytes)
	}
	terms := []auth.Term{programName, serializedObjectId}
	if params.CanReadTerms != nil {
		terms = params.CanReadTerms
	}
	var canRead auth.Form
	if params.CanRead != nil {
		canRead = params.CanRead
	} else {
		canRead = auth.Pred{
			Name: CanReadPredicate,
			Arg:  terms,
		}
	}
	policyKey, err := tao.NewTemporaryKeys(tao.Signing)
	if err != nil {
		return nil, nil, err
	}
	var says auth.Form
	if params.Says != nil {
		says = params.Says
	} else {
		says = auth.Says{
			Speaker:    policyKey.SigningKey.ToPrincipal(),
			Time:       nil,
			Expiration: nil,
			Message:    canRead,
		}
	}
	serializedSays := auth.Marshal(says)
	var directiveType *DirectiveMessageDirectiveType
	if params.DirectiveType != nil {
		directiveType = params.DirectiveType
	} else {
		directiveType = DirectiveMessage_SECRET_DISCLOSURE.Enum()
	}
	var signature []byte
	if params.Signature != nil {
		signature = params.Signature
	} else {
		signature, err = policyKey.SigningKey.Sign(serializedSays, SigningContext)
		if err != nil {
			return nil, nil, err
		}
	}
	var signer []byte
	if params.Signer != nil {
		signer = params.Signer
	} else {
		signer = auth.Marshal(policyKey.SigningKey.ToPrincipal())
	}
	directive := &DirectiveMessage{
		Type:                directiveType,
		SerializedStatement: serializedSays,
		Signature:           signature,
		Signer:              signer,
	}
	return policyKey, directive, nil
}
