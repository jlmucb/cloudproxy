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
	"errors"

	"github.com/golang/protobuf/proto"
	po "github.com/jlmucb/cloudproxy/go/support_libraries/protected_objects"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

const (
	SigningContext   = "Policy Secret Disclosure Directive Signature"
	CanReadPredicate = "CanRead"
)

// This function returns a secret disclosure directive signed by policyKey with the statement:
//     'policyKey says programName can read protectedObjectId'.
func CreateSecretDisclosureDirective(policyKey *tao.Keys, programName *auth.Prin,
	protectedObjId *po.ObjectIdMessage) (*DirectiveMessage, error) {

	// Construct serialized 'says' statement.
	serializedObjId, err := proto.Marshal(protectedObjId)
	if err != nil {
		return nil, err
	}
	canRead := auth.MakePredicate(CanReadPredicate, *programName, serializedObjId)
	statement := auth.Says{
		Speaker:    policyKey.SigningKey.ToPrincipal(),
		Time:       nil, // TODO: For now, time and exp not implemented.
		Expiration: nil,
		Message:    canRead,
	}
	serializedStatement := auth.Marshal(statement)

	// Sign serialized statement.
	signature, err := policyKey.SigningKey.Sign(serializedStatement, SigningContext)
	if err != nil {
		return nil, err
	}

	// Construct and return directive.
	directive := &DirectiveMessage{
		Type:                DirectiveMessage_SECRET_DISCLOSURE.Enum(),
		SerializedStatement: serializedStatement,
		Signature:           signature,
		Signer:              auth.Marshal(policyKey.SigningKey.ToPrincipal()),
	}
	return directive, nil
}

// This function performs the following checks on a secret disclosure directive.
// (1) policyKey matches the signer of the directive (delegation not supported as of now).
// (2) the directive signature is valid with respect to policyKey
// (3) the directive message is a statement of the form:
//         'policyKey says programName can read protectedObjectId'.
//     where programName is a Tao Principal and protectedObjectId is a (serialized) protected
//     object message id.
func VerifySecretDisclosureDirective(policyKey *tao.Keys,
	directive *DirectiveMessage) (*auth.Prin, *po.ObjectIdMessage, error) {

	// Check type of directive
	if directive.Type == nil || *(directive.Type) != DirectiveMessage_SECRET_DISCLOSURE {
		return nil, nil, errors.New(
			"secret_disclosure: directive not of secret disclosure type.")
	}

	// Check directive signer matches policy key.
	if bytes.Compare(
		auth.Marshal(policyKey.SigningKey.ToPrincipal()), directive.GetSigner()) != 0 {
		return nil, nil, errors.New(
			"secret_disclosure: directive signer doesn't match policy key.")
	}

	// Verify signature.
	ok, err := policyKey.SigningKey.GetVerifier().Verify(
		directive.GetSerializedStatement(), SigningContext, directive.GetSignature())
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, errors.New("secret_disclosure: directive signature check failed.")
	}

	// Validate and return statement.
	statement, err := auth.UnmarshalForm(directive.GetSerializedStatement())
	if err != nil {
		return nil, nil, err
	}
	var saysStatement *auth.Says
	if ptr, ok := statement.(*auth.Says); ok {
		saysStatement = ptr
	} else if val, ok := statement.(auth.Says); ok {
		saysStatement = &val
	} else {
		return nil, nil, errors.New("secret_disclosure: directive statement not a 'Says'.")
	}
	pred, ok := saysStatement.Message.(auth.Pred)
	if !ok {
		return nil, nil, errors.New("secret_disclosure: directive message not a 'Pred'.")
	}
	if pred.Name != CanReadPredicate {
		return nil, nil, errors.New("secret_disclosure: directive predicate not a 'CanRead'.")
	}
	if len(pred.Arg) != 2 {
		return nil, nil, errors.New(
			"secret_disclosure: directive 'CanRead' doesn't have 2 terms.")
	}
	programName, ok := pred.Arg[0].(auth.Prin)
	if !ok {
		return nil, nil, errors.New(
			"secret_disclosure: directive programName Term not of type auth.Prin.")
	}
	serializedObjId, ok := pred.Arg[1].(auth.Bytes)
	if !ok {
		return nil, nil, errors.New(
			"secret_disclosure: directive ObjId Term not of type []byte.")
	}
	protectedObjId := po.ObjectIdMessage{}
	err = proto.Unmarshal(serializedObjId, &protectedObjId)
	if err != nil {
		return nil, nil, errors.New(
			"secret_disclosure: error deserializing protected ObjId.")
	}
	return &programName, &protectedObjId, nil
}
