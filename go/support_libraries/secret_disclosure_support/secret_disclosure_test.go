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
	"fmt"
	"os"
	"testing"

	"github.com/golang/protobuf/proto"
	po "github.com/jlmucb/cloudproxy/go/support_libraries/protected_objects"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

var Delegate = auth.Prin{
	Type: "program",
	Key:  auth.Bytes([]byte(`fake program`)),
}

var Delegator = auth.Prin{
	Type: "program",
	Key:  auth.Bytes([]byte(`speaker program`)),
}

var ProtectedObjectName = "obj_name"
var ProtectedObjectEpoch = int32(0)
var ProtectedObjectId = po.ObjectIdMessage{
	ObjName:  &ProtectedObjectName,
	ObjEpoch: &ProtectedObjectEpoch,
}

var us = "US"
var google = "Google"
var x509Info = tao.X509Details{
	Country:      &us,
	Organization: &google}

func TestProcessDirectiveAndUpdateGuard(t *testing.T) {
	domain := setUpDomain(t)
	err := domain.Guard.Authorize(Delegator, OwnPredicate,
		[]string{ProtectedObjectId.String()})
	failOnError(t, err)

	programKey, err := tao.NewTemporaryKeys(tao.Signing)
	failOnError(t, err)
	info := x509Info
	speakerStr := Delegator.String()
	info.OrganizationalUnit = &speakerStr
	subject := tao.NewX509Name(&info)
	programKey.Cert, err = domain.Keys.SigningKey.CreateSignedX509(
		domain.Keys.Cert, 1, programKey.SigningKey.GetVerifier(), subject)
	failOnError(t, err)
	directive, err := CreateSecretDisclosureDirective(programKey, &Delegator,
		&Delegate, ReadPredicate, &ProtectedObjectId)
	failOnError(t, err)
	directive.Cert = programKey.Cert.Raw

	err = ProcessDirectiveAndUpdateGuard(domain, directive)
	failOnError(t, err)

	if !domain.Guard.IsAuthorized(Delegate, ReadPredicate,
		[]string{ProtectedObjectId.String()}) {
		t.Fatal("Domain guard not updated as expected.")
	}

	tearDown(t)
}

func TestCreateDirective(t *testing.T) {
	policyKey, testDirective, err := generatePolicyKeyAndSignedDirective(Params{})
	failOnError(t, err)
	signer := policyKey.SigningKey.ToPrincipal()
	directive, err := CreateSecretDisclosureDirective(policyKey, &signer, &Delegate,
		ReadPredicate, &ProtectedObjectId)
	failOnError(t, err)
	signatureValid, err := policyKey.SigningKey.GetVerifier().Verify(
		directive.SerializedStatement, SigningContext, directive.Signature)
	failOnError(t, err)
	if !signatureValid {
		t.Fatal("Signature on directive not valid")
	}
	if testDirective.GetType() != directive.GetType() ||
		!bytes.Equal(testDirective.GetSerializedStatement(),
			directive.GetSerializedStatement()) ||
		!bytes.Equal(testDirective.GetSigner(), directive.GetSigner()) {
		t.Fatal("Fields in directive do not match expected value")
	}
}

func TestVerifyDirective(t *testing.T) {
	policyKey, directive, err := generatePolicyKeyAndSignedDirective(Params{})
	failOnError(t, err)
	prin, programName, pred, protectedObjectId, err :=
		VerifySecretDisclosureDirective(policyKey, directive)
	failOnError(t, err)
	if !prin.Identical(policyKey.SigningKey.ToPrincipal()) {
		t.Fatal("Verify returns different speaker principal from expected value.")
	}
	if !Delegate.Identical(programName) {
		t.Fatal("Verify returns different programName from expected value.")
	}
	if *pred != ReadPredicate {
		t.Fatal("Verify returns different predicate name from expected value.")
	}
	if *protectedObjectId.ObjName != *ProtectedObjectId.ObjName ||
		*protectedObjectId.ObjEpoch != *ProtectedObjectId.ObjEpoch {
		t.Fatal("Verify returns different protectedObjectId from expected value.")
	}
}

func TestCreateAndVerifyDirective(t *testing.T) {
	policyKey, _, err := generatePolicyKeyAndSignedDirective(Params{})
	failOnError(t, err)
	signer := policyKey.SigningKey.ToPrincipal()
	directive, err := CreateSecretDisclosureDirective(policyKey, &signer, &Delegate,
		ReadPredicate, &ProtectedObjectId)
	failOnError(t, err)
	prin, programName, pred, protectedObjectId, err := VerifySecretDisclosureDirective(policyKey,
		directive)
	failOnError(t, err)
	if !prin.Identical(policyKey.SigningKey.ToPrincipal()) {
		t.Fatal("Verify returns different speaker principal from expected value.")
	}
	if !Delegate.Identical(programName) {
		t.Fatal("Verify returns different programName from expected value.")
	}
	if *pred != ReadPredicate {
		t.Fatal("Verify returns different predicate name from expected value.")
	}
	if *protectedObjectId.ObjName != *ProtectedObjectId.ObjName ||
		*protectedObjectId.ObjEpoch != *ProtectedObjectId.ObjEpoch {
		t.Fatal("Verify returns different protectedObjectId from expected value.")
	}
}

func TestCreateAndVerifyDirectiveSignedByProgram(t *testing.T) {
	policyKey, _, err := generatePolicyKeyAndSignedDirective(Params{})
	programKey, err := tao.NewTemporaryKeys(tao.Signing)
	failOnError(t, err)
	info := x509Info
	speakerStr := Delegator.String()
	info.OrganizationalUnit = &speakerStr
	subject := tao.NewX509Name(&info)
	programKey.Cert, err = policyKey.SigningKey.CreateSignedX509(
		policyKey.Cert, 1, programKey.SigningKey.GetVerifier(), subject)
	failOnError(t, err)
	directive, err := CreateSecretDisclosureDirective(programKey, &Delegator,
		&Delegate, ReadPredicate, &ProtectedObjectId)
	failOnError(t, err)
	directive.Cert = programKey.Cert.Raw

	speaker, prog, pred, pobj, err := VerifySecretDisclosureDirective(policyKey, directive)
	failOnError(t, err)
	if !speaker.Identical(Delegator) {
		t.Fatal(fmt.Sprintf("verify returns Speaker %v different from expected value %v",
			speaker, Delegator))
	}
	if !prog.Identical(Delegate) {
		t.Fatal(fmt.Sprintf("verify returns program  %v different from expected value %v",
			prog, Delegate))
	}
	if *pred != ReadPredicate {
		t.Fatal(fmt.Sprintf("verify returns predicate  %v different from expected value %v",
			pred, ReadPredicate))
	}
	if *pobj.ObjName != *ProtectedObjectId.ObjName ||
		*pobj.ObjEpoch != *ProtectedObjectId.ObjEpoch {
		t.Fatal("Verify returns different protectedObjectId from expected value.")
	}
}

func TestVerifyDirectiveWithBadType(t *testing.T) {
	policyKey, testDirective, err := generatePolicyKeyAndSignedDirective(Params{})
	failOnError(t, err)
	testDirective.Type = nil
	_, _, _, _, err = VerifySecretDisclosureDirective(policyKey, testDirective)
	if err == nil {
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
	var con auth.Form
	con = auth.Const(true)
	params := Params{
		Says: &con,
	}
	expectError(&params, t)
}

func TestVerifyDirectiveWithBadPredicate_badName(t *testing.T) {
	var form auth.Form
	form = auth.Pred{
		Name: "CanNotRead",
	}
	params := Params{
		CanRead: &form,
	}
	expectError(&params, t)
}

func TestVerifyDirectiveWithBadPredicate_badTerms(t *testing.T) {
	var form auth.Form
	form = auth.Pred{
		Name: ReadPredicate,
		Arg:  []auth.Term{auth.Int(0), auth.Str(""), auth.Str("a")},
		// TODO: Note make([]auth.Term, 3) above causes NPE in auth.Marshal(thisPred)
		// Is that a bug?
	}
	params := Params{
		CanRead: &form,
	}
	expectError(&params, t)
}

func TestVerifyDirectiveWithBadDelegate(t *testing.T) {
	var term auth.Term
	term = auth.Str("")
	params := Params{
		Delegate: &term,
	}
	expectError(&params, t)
}

func TestVerifyDirectiveWithBadProtectedObjectId_invalidType(t *testing.T) {
	var term auth.Term
	term = auth.Str("")
	params := Params{
		SerializedObjectId: &term,
	}
	expectError(&params, t)
}

func TestVerifyDirectiveWithBadProtectedObjectId_invalidProtoBuf(t *testing.T) {
	var term auth.Term
	term = auth.Bytes([]byte("bad bytes"))
	params := Params{
		SerializedObjectId: &term,
	}
	expectError(&params, t)
}

func expectError(params *Params, t *testing.T) {
	policyKey, testDirective, err := generatePolicyKeyAndSignedDirective(*params)
	failOnError(t, err)
	testDirective.Type = nil
	_, _, _, _, err = VerifySecretDisclosureDirective(policyKey, testDirective)
	if err == nil {
		t.Fatal("Verify output is not an error")
	}
}

func failOnError(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

type Params struct {
	Delegate           *auth.Term
	SerializedObjectId *auth.Term
	Says               *auth.Form
	CanRead            *auth.Form
	CanReadTerms       []auth.Term
	Signer             []byte
	Signature          []byte
	DirectiveType      *DirectiveMessageDirectiveType
}

func generatePolicyKeyAndSignedDirective(params Params) (*tao.Keys, *DirectiveMessage, error) {
	var programName auth.Term
	if params.Delegate != nil {
		programName = *params.Delegate
	} else {
		programName = Delegate
	}
	var serializedObjectId auth.Term
	if params.SerializedObjectId != nil {
		serializedObjectId = *params.SerializedObjectId
	} else {
		bytes, err := proto.Marshal(&ProtectedObjectId)
		if err != nil || len(bytes) == 0 {
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
		canRead = *params.CanRead
	} else {
		canRead = auth.Pred{
			Name: ReadPredicate,
			Arg:  terms,
		}
	}
	policyKey, err := tao.NewTemporaryKeys(tao.Signing)
	if err != nil {
		return nil, nil, err
	}
	info := x509Info
	name := policyKey.SigningKey.ToPrincipal().String()
	info.OrganizationalUnit = &name
	subject := tao.NewX509Name(&info)
	policyKey.Cert, err = policyKey.SigningKey.CreateSelfSignedX509(subject)
	if err != nil {
		return nil, nil, err
	}
	var says auth.Form
	if params.Says != nil {
		says = *params.Says
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

func setUpDomain(t *testing.T) *tao.Domain {
	var err error
	if _, err = os.Stat("./tmpdir"); os.IsNotExist(err) {
		err = os.Mkdir("./tmpdir", 0777)
		if err != nil {
			t.Fatal(err)
		}
	}
	aclGuardType := "ACLs"
	aclGuardPath := "acls"
	cfg := tao.DomainConfig{
		DomainInfo: &tao.DomainDetails{
			GuardType: &aclGuardType},
		AclGuardInfo: &tao.ACLGuardDetails{
			SignedAclsPath: &aclGuardPath}}
	domain, err := tao.CreateDomain(cfg, "./tmpdir/domain", []byte("xxx"))
	if err != nil {
		t.Fatal(err)
	}
	return domain
}

func tearDown(t *testing.T) {
	err := os.RemoveAll("./tmpdir")
	if err != nil {
		t.Fatal(err)
	}
}
