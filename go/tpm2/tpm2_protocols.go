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
//

package tpm2

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	// "github.com/golang/protobuf/proto"
)

const (
	PrimaryKeyHandle uint32 = 0x810003e8
	QuoteKeyHandle uint32 =  0x810003e9
	StoreKeyHandle uint32 =  0
	RollbackKeyHandle uint32 =  0
)

// return handle, policy digest
func assistCreateSession(rw io.ReadWriter, hash_alg uint16,
		pcrs []int) (Handle, []byte, error) {
	nonceCaller := []byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	var secret []byte
	sym := uint16(AlgTPM_ALG_NULL)

	session_handle, policy_digest, err := StartAuthSession(rw, Handle(OrdTPM_RH_NULL),
		Handle(OrdTPM_RH_NULL), nonceCaller, secret,
		uint8(OrdTPM_SE_POLICY), sym, hash_alg)
	if err != nil {
		return Handle(0), nil, errors.New("Can't start session")
	}

	err = PolicyPassword(rw, session_handle)
	if err != nil {
		return Handle(0), nil, errors.New("PolicyPcr fails")
	}
	var tpm_digest []byte
	err = PolicyPcr(rw, session_handle, tpm_digest, pcrs)
	if err != nil {
		return Handle(0), nil, errors.New("PolicyPcr fails")
	}

	policy_digest, err = PolicyGetDigest(rw, session_handle)
	if err != nil {
		return Handle(0), nil, errors.New("PolicyPcr fails")
	}
	return session_handle, policy_digest, nil
}

// out: private, public
func assistSeal(rw io.ReadWriter, parentHandle Handle, toSeal []byte,
	parentPassword string, ownerPassword string, pcrs []int,
	policy_digest []byte) ([]byte, []byte, error) {

	var empty []byte
	keyedhashparms := KeyedHashParams{uint16(AlgTPM_ALG_KEYEDHASH),
		uint16(AlgTPM_ALG_SHA1),
		FlagSealDefault, empty, uint16(AlgTPM_ALG_AES), uint16(128),
		uint16(AlgTPM_ALG_CFB), uint16(AlgTPM_ALG_NULL), empty}
	private_blob, public_blob, err := CreateSealed(rw, parentHandle,
		policy_digest, parentPassword, ownerPassword, toSeal,
		[]int{7}, keyedhashparms)
	if err != nil {
		return nil, nil, errors.New("CreateSealed fails") 
	}
	return private_blob, public_blob, nil
}

// out: unsealed blob, nonce
func assistUnseal(rw io.ReadWriter, sessionHandle Handle, primaryHandle Handle,
	pub []byte, priv []byte, parentPassword string, ownerPassword string,
	policy_digest []byte) ([]byte, []byte, error) {

	// Load Sealed
	sealHandle, _, err := Load(rw, primaryHandle, parentPassword,
		ownerPassword, pub, priv)
	if err != nil {
		FlushContext(rw, sessionHandle)
		return nil, nil, errors.New("Load failed")
	}

	// Unseal
	unsealed, nonce, err := Unseal(rw, sealHandle, ownerPassword,
		sessionHandle, policy_digest)
	if err != nil {
		FlushContext(rw, sessionHandle)
		return nil, nil, errors.New("Unseal failed")
	}
	return unsealed, nonce, err
}


// This program creates a key hierarchy consisting of a
// primary key and quoting key for cloudproxy
// and makes their handles permanent.
func CreateTpm2KeyHierarchy(rw io.ReadWriter, pcrs []int, keySize int, hash_alg_id uint16,
		primaryHandle uint32, quoteHandle uint32, quotePassword string) (error) {

	modSize := uint16(keySize)

	// Remove old permanent handles
	err := EvictControl(rw, Handle(OrdTPM_RH_OWNER), Handle(primaryHandle),
			Handle(primaryHandle))
	if err != nil {
		fmt.Printf("Evict existing permanant primary handle failed (OK)\n")
	}
	err = EvictControl(rw, Handle(OrdTPM_RH_OWNER), Handle(quoteHandle),
		Handle(quoteHandle))
	if err != nil {
		fmt.Printf("Evict existing permanant quote handle failed (OK)\n")
	}

	// CreatePrimary
	var empty []byte
	primaryparms := RsaParams{uint16(AlgTPM_ALG_RSA), uint16(AlgTPM_ALG_SHA1),
		FlagStorageDefault, empty, uint16(AlgTPM_ALG_AES), uint16(128),
		uint16(AlgTPM_ALG_CFB), uint16(AlgTPM_ALG_NULL),
		uint16(0), modSize, uint32(0x00010001), empty}
	tmpPrimaryHandle, public_blob, err := CreatePrimary(rw, uint32(OrdTPM_RH_OWNER), pcrs,
		"", "", primaryparms)
	if err != nil {
		return errors.New("CreatePrimary failed")
	}

	// CreateKey (Quote Key)
	keyparms := RsaParams{uint16(AlgTPM_ALG_RSA), uint16(AlgTPM_ALG_SHA1),
		FlagSignerDefault, empty, uint16(AlgTPM_ALG_NULL), uint16(0),
		uint16(AlgTPM_ALG_ECB), uint16(AlgTPM_ALG_RSASSA), uint16(AlgTPM_ALG_SHA1),
		modSize, uint32(0x00010001), empty}
	private_blob, public_blob, err := CreateKey(rw,
		uint32(tmpPrimaryHandle), pcrs, "", quotePassword, keyparms)
	if err != nil {
		return errors.New("Can't create quote key")
	}

	// Load
	tmpQuoteHandle, _, err := Load(rw, tmpPrimaryHandle, "", quotePassword,
	     public_blob, private_blob)
	if err != nil {
		return errors.New("Load failed")
	}

	// Install new handles
	err = EvictControl(rw, Handle(OrdTPM_RH_OWNER), tmpPrimaryHandle, Handle(primaryHandle))
	if err != nil {
		FlushContext(rw, tmpPrimaryHandle)
		FlushContext(rw, tmpQuoteHandle)
		return errors.New("Install new primary handle failed")
	}
	err = EvictControl(rw, Handle(OrdTPM_RH_OWNER), tmpQuoteHandle,
			Handle(quoteHandle))
	if err != nil {
		FlushContext(rw, tmpQuoteHandle)
		return errors.New("Install new quote handle failed")
	}
	return nil
}

func Tpm2DomainProgramKeyServer(policyCert []byte, policyKey *rsa.PrivateKey) {
	//, signing_instructions_message *tpm2.SigningInstructionsMessage) {

	// Server response.
        // response, err := tpm.ConstructServerResponse(policyPrivateKey,
        //         derPolicyCert, *signing_instructions_message, *request)
	// cert, err := tpm.ClientDecodeServerResponse(rw, protectorHandle,
        //      tpm.Handle(*permQuoteHandle), *quoteOwnerPassword, *response)
}

func Tpm2DomainProgramKeyClient(/* Tao, */ programName string, programKey *rsa.PrivateKey,
	ekCert []byte) {
	// protoClientPrivateKey, request, err := tpm.ConstructClientRequest(rw,
        //         derEndorsementCert, tpm.Handle(*permQuoteHandle), "",
        //         *quoteOwnerPassword, prog_name)
}

