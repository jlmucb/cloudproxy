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
// 'PolicyKey/DelegatorProgram says DelegateProgram can Read/Write/Create/Delete/Own ProtectedObjectId'

package secret_disclosure

import (
	"bytes"
	"crypto/x509"
	"errors"

	"github.com/golang/protobuf/proto"
	po "github.com/jlmucb/cloudproxy/go/support_libraries/protected_objects"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

const (
	SigningContext  = "Policy Secret Disclosure Directive Signature"
	ReadPredicate   = "Read"
	WritePredicate  = "Write"
	CreatePredicate = "Create"
	DeletePredicate = "Delete"
	OwnPredicate    = "Own"
)

func ProcessDirectiveAndUpdateGuard(domain *tao.Domain, directive *DirectiveMessage) error {
	delegator, delegate, pred, pObj, err := VerifySecretDisclosureDirective(domain.Keys, directive)
	if err != nil {
		return err
	}
	if domain.Guard.IsAuthorized(*delegate, *pred, []string{pObj.String()}) {
		return nil
	}
	if !domain.Guard.IsAuthorized(*delegator, OwnPredicate, []string{pObj.String()}) {
		return errors.New("speaker of directive is not owner of object")
	}
	return domain.Guard.Authorize(*delegate, *pred, []string{pObj.String()})

}

// This function returns a secret disclosure directive signed by key with the statement:
// 'delegator says delegate predicate protectedObjectId'.
func CreateSecretDisclosureDirective(key *tao.Keys, delegator, delegate *auth.Prin,
	predicate string, protectedObjId *po.ObjectIdMessage) (*DirectiveMessage, error) {

	// Construct serialized 'says' statement.
	serializedObjId, err := proto.Marshal(protectedObjId)
	if err != nil {
		return nil, err
	}
	pred := auth.MakePredicate(predicate, *delegate, serializedObjId)
	statement := auth.Says{
		Speaker:    *delegator,
		Time:       nil, // TODO: For now, time and exp not implemented.
		Expiration: nil,
		Message:    pred,
	}
	serializedStatement := auth.Marshal(statement)

	// Sign serialized statement.
	signature, err := key.SigningKey.Sign(serializedStatement, SigningContext)
	if err != nil {
		return nil, err
	}

	// Construct and return directive.
	directive := &DirectiveMessage{
		Type:                DirectiveMessage_SECRET_DISCLOSURE.Enum(),
		SerializedStatement: serializedStatement,
		Signature:           signature,
		Signer:              auth.Marshal(key.SigningKey.ToPrincipal()),
		Cert:                key.Cert.Raw,
	}
	return directive, nil
}

// This function performs the following checks on a secret disclosure directive.
// (1) the directive signature is valid with respect to signerKey of directive
// (2) Either
//       - policyKey matches the signerKey of directive
//       - directive cert is a valid program cert (signed by policyKey) certifying the signerKey
//         of directive as belonging to 'delegator'
// (3) the directive message is a statement of the form:
//         'policyKey/'delegator' says delegate can read protectedObjectId'
//     where delegate is a Tao Principal and protectedObjectId is a (serialized) protected
//     object message id.
func VerifySecretDisclosureDirective(policyKey *tao.Keys, directive *DirectiveMessage) (*auth.Prin,
	*auth.Prin, *string, *po.ObjectIdMessage, error) {

	// Check type of directive
	if directive.Type == nil || *(directive.Type) != DirectiveMessage_SECRET_DISCLOSURE {
		return nil, nil, nil, nil, errors.New(
			"secret_disclosure: directive not of secret disclosure type.")
	}

	var verifier *tao.Verifier
	var delegatorStr string
	// Check directive signer matches policy key.
	if bytes.Compare(
		auth.Marshal(policyKey.SigningKey.ToPrincipal()), directive.GetSigner()) == 0 {
		verifier = policyKey.SigningKey.GetVerifierFromSigner()
		delegatorStr = verifier.ToPrincipal().String()

	} else {
		// Check if program cert is valid, signed by policy key,
		// cert public key matches signer and cert name matches speaker
		// of says statement.
		cert, err := x509.ParseCertificate(directive.Cert)
		if err != nil {
			return nil, nil, nil, nil, errors.New(
				"error parsing directive program cert")
		}
		rootCert := x509.NewCertPool()
		rootCert.AddCert(policyKey.Cert)
		verifyOptions := x509.VerifyOptions{Roots: rootCert}
		_, err = cert.Verify(verifyOptions)
		if err != nil {
			return nil, nil, nil, nil, errors.New(
				"program cert not valid")
		}
		verifier, err = tao.VerifierFromX509(cert)
		delegatorStr = cert.Subject.CommonName
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if bytes.Compare(auth.Marshal(verifier.ToPrincipal()), directive.GetSigner()) != 0 {
			return nil, nil, nil, nil, errors.New(
				"secret_disclosure: directive signer doesn't match program key.")
		}
	}

	// Verify signature.
	ok, err := verifier.Verify(directive.GetSerializedStatement(), SigningContext,
		directive.GetSignature())
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if !ok {
		return nil, nil, nil, nil,
			errors.New("secret_disclosure: directive signature check failed.")
	}

	// Validate and return statement.
	statement, err := auth.UnmarshalForm(directive.GetSerializedStatement())
	if err != nil {
		return nil, nil, nil, nil, err
	}
	var saysStatement *auth.Says
	if ptr, ok := statement.(*auth.Says); ok {
		saysStatement = ptr
	} else if val, ok := statement.(auth.Says); ok {
		saysStatement = &val
	} else {
		return nil, nil, nil, nil,
			errors.New("secret_disclosure: directive statement not a 'Says'")
	}
	stmtSpeaker, ok := saysStatement.Speaker.(auth.Prin)
	if !ok {
		return nil, nil, nil, nil,
			errors.New("secret_disclosure: directive speaker not a 'Prin'")
	}
	if stmtSpeaker.String() != delegatorStr {
		return nil, nil, nil, nil, errors.New(
			"secret_disclosure: directive statement speaker does not match signer")
	}
	pred, ok := saysStatement.Message.(auth.Pred)
	if !ok {
		return nil, nil, nil, nil,
			errors.New("secret_disclosure: directive message not a 'Pred'")
	}
	predName := pred.Name
	if predName == "" {
		return nil, nil, nil, nil,
			errors.New("secret_disclosure: directive predicate name is empty")
	}
	if len(pred.Arg) != 2 {
		return nil, nil, nil, nil,
			errors.New("secret_disclosure: directive predicate doesn't have 2 terms")
	}
	delegateName, ok := pred.Arg[0].(auth.Prin)
	if !ok {
		return nil, nil, nil, nil, errors.New(
			"secret_disclosure: directive delegateName Term not of type auth.Prin.")
	}
	serializedObjId, ok := pred.Arg[1].(auth.Bytes)
	if !ok {
		return nil, nil, nil, nil, errors.New(
			"secret_disclosure: directive ObjId Term not of type []byte.")
	}
	protectedObjId := po.ObjectIdMessage{}
	err = proto.Unmarshal(serializedObjId, &protectedObjId)
	if err != nil {
		return nil, nil, nil, nil, errors.New(
			"secret_disclosure: error deserializing protected ObjId.")
	}
	return &stmtSpeaker, &delegateName, &predName, &protectedObjId, nil
}
