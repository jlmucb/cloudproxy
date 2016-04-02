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

package tpm2

import (
	"bytes"
	"crypto/rsa"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"math/big"
        "testing"
	"time"

	"github.com/jlmucb/cloudproxy/go/tpm2"
	"github.com/golang/protobuf/proto"
)

func RestCreateKeyHierarchy(t *testing.T) {
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if (err != nil) {
		t.Fatal("Can't open tpm")
	}
	defer rw.Close()

	err = tpm2.CreateTpm2KeyHierarchy(rw, []int{7}, 2048,
			tpm2.AlgTPM_ALG_SHA1,
			tpm2.RootKeyHandle, tpm2.QuoteKeyHandle, "01020304")
	if (err != nil) {
		fmt.Printf("err: %s\n", err)
		t.Fatal("Can't create key hierarchy")
	}
}

func TestMakeEndorsementCert(t *testing.T) {
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatal("Can't open tpm")
	}
	defer rw.Close()

	var notBefore time.Time
        notBefore = time.Now()
        validFor := 365*24*time.Hour
        notAfter := notBefore.Add(validFor)

	policyKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("Can't generate policy key\n")
	}
	derPolicyCert, err := tpm2.GenerateSelfSignedCertFromKey(policyKey,
		"Cloudproxy Authority", "Application Policy Key",
		tpm2.GetSerialNumber(), notBefore, notAfter)
	if err != nil {
		t.Fatal("Can't generate policy key\n")
	}
	fmt.Printf("policyKey: %x\n", policyKey)

	endorsementHandle, _, err := tpm2.CreateEndorsement(rw, 2048, []int{7})
	if err != nil {
		t.Fatal("Can't CreateEndorsement")
	}
	endorsementCert, err := tpm2.GenerateHWCert(rw,
		endorsementHandle, "JohnsHw", notBefore,
		notAfter, tpm2.GetSerialNumber(), derPolicyCert, policyKey)
	if err != nil {
		t.Fatal("Can't create endorsement cert")
	}
	fmt.Printf("Endorsement cert: %x\n", endorsementCert)
	ioutil.WriteFile("./tmptest/policy_cert.test", derPolicyCert, 0644)
	ioutil.WriteFile("./tmptest/endorsement_cert.test", endorsementCert, 0644)
	tpm2.FlushContext(rw, endorsementHandle)
}

func RestSeal(t *testing.T) {
}

func TestUnseal(t *testing.T) {
}

func TestAttest(t *testing.T) {
}

func RestSignAttest(t *testing.T) {
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if (err != nil) {
		t.Fatal("Can't open tpm")
	}
	defer rw.Close()

	var notBefore time.Time
        notBefore = time.Now()
        validFor := 365*24*time.Hour
        notAfter := notBefore.Add(validFor)

	policyKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("Can't generate policy key\n")
	}
	derPolicyCert, err := tpm2.GenerateSelfSignedCertFromKey(policyKey,
		"Cloudproxy Authority", "Application Policy Key",
		tpm2.GetSerialNumber(), notBefore, notAfter)
	if err != nil {
		t.Fatal("Can't generate policy key\n")
	}
	fmt.Printf("policyKey: %x\n", policyKey)
	attestCert, err := tpm2.GenerateHWCert(rw, tpm2.Handle(tpm2.QuoteKeyHandle),
		"JohnsHw", notBefore, notAfter,
		tpm2.GetSerialNumber(), derPolicyCert, policyKey)
	if err != nil {
		t.Fatal("Can't create attest cert")
	}
	fmt.Printf("Attest cert: %x\n", attestCert)
	ioutil.WriteFile("./tmptest/policy_cert.test", derPolicyCert, 0644)
	ioutil.WriteFile("./tmptest/attest_cert.test", attestCert, 0644)
}

// Combined Activate test
func TestMakeActivate(t *testing.T) {

	// Open tpm
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}
	defer rw.Close()

	// Generate Credential
	credential := []byte{1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf,0x10}
	fmt.Printf("Credential: %x\n", credential)

	var empty []byte
	// CreatePrimary
	primaryparms := tpm2.RsaParams{uint16(tpm2.AlgTPM_ALG_RSA),
		uint16(tpm2.AlgTPM_ALG_SHA1), tpm2.FlagStorageDefault, empty,
		uint16(tpm2.AlgTPM_ALG_AES), uint16(128),
		uint16(tpm2.AlgTPM_ALG_CFB), uint16(tpm2.AlgTPM_ALG_NULL),
		uint16(0), uint16(2048), uint32(0x00010001), empty}
	parent_handle, primary_public_blob, err := tpm2.CreatePrimary(rw,
		uint32(tpm2.OrdTPM_RH_OWNER), []int{0x7}, "", "", primaryparms)
	if err != nil {
		t.Fatal("CreatePrimary fails")
	}
	fmt.Printf("CreatePrimary succeeded\n")

	endorseParams, err := tpm2.DecodeRsaArea(primary_public_blob)
	if err != nil {
		t.Fatal("DecodeRsaBuf fails", err)
	}

	// Replace with key_handle = tpm2.QuoteKeyHandle
	// CreateKey
	keyparms := tpm2.RsaParams{uint16(tpm2.AlgTPM_ALG_RSA), uint16(tpm2.AlgTPM_ALG_SHA1),
                tpm2.FlagSignerDefault, empty, uint16(tpm2.AlgTPM_ALG_NULL), uint16(0),
                uint16(tpm2.AlgTPM_ALG_ECB), uint16(tpm2.AlgTPM_ALG_RSASSA),
                uint16(tpm2.AlgTPM_ALG_SHA1), 2048, uint32(0x00010001), empty}
	private_blob, public_blob, err := tpm2.CreateKey(rw, uint32(parent_handle),
		[]int{7}, "", "", keyparms)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("CreateKey fails")
	}
	fmt.Printf("CreateKey succeeded\n")

	// Load
	key_handle, _, err := tpm2.Load(rw, parent_handle, "", "",
	     public_blob, private_blob)
	if err != nil {
		t.Fatal("Load fails")
	}
	fmt.Printf("Load succeeded\n")

/*
	parent_handle := tpm2.Handle(tpm2.RootKeyHandle)
	key_handle := tpm2.Handle(tpm2.QuoteKeyHandle)

	root_public, _, _, err := tpm2.ReadPublic(rw, parent_handle)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("ReadPublic (1) fails")
	}
	fmt.Printf("root public: %x\n", root_public)
	endorseParams, err := tpm2.DecodeRsaBuf(root_public)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("DecodeRsaBuf fails")
	}
*/

	// ReadPublic
	_, name, _, err := tpm2.ReadPublic(rw, key_handle)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("ReadPublic fails")
	}
	fmt.Printf("ReadPublic succeeded\n")

// DELETE FROM HERE
	// Internal MakeCredential
	credBlob, encrypted_secret0, err := tpm2.InternalMakeCredential(rw,
		parent_handle, credential, name)
	if err != nil {
		t.Fatal("Can't InternalMakeCredential\n")
	}

	// ActivateCredential
	// recovered_credential1, err := tpm2.ActivateCredential(rw, key_handle, parent_handle,
	recovered_credential1, err := tpm2.ActivateCredential(rw, key_handle,
		parent_handle,
		"", "", credBlob, encrypted_secret0)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("Can't ActivateCredential\n")
	}
	if bytes.Compare(credential, recovered_credential1) != 0 {
		t.Fatal("Credential and recovered credential differ\n")
	}
	fmt.Printf("InternalMake/Activate test succeeds\n\n")
// DELETE TO HERE

/*
 	notBefore = time.Now()
        validFor := 365*24*time.Hour
        notAfter := notBefore.Add(validFor)

        policyKey, err := rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
                t.Fatal("Can't generate policy key\n")
        }
        derPolicyCert, err := tpm2.GenerateSelfSignedCertFromKey(policyKey,
                "Cloudproxy Authority", "Application Policy Key",
                tpm2.GetSerialNumber(), notBefore, notAfter)
        if err != nil {
                t.Fatal("Can't generate policy key\n")
        }
        fmt.Printf("policyKey: %x\n", policyKey)
	derEndorsementCert, err := tpm2.GenerateHWCert(rw,
        tpm2.Handle(tpm2.PrimaryKeyHandle), "JohnsHw", notBefore,
        notAfter, tpm2.GetSerialNumber(), derPolicyCert, policyKey)
	cert, err := x509.ParseCertificate(derEndorsementCert)
	protectorPublic, err := GetPublicKeyFromDerCert(derEndorsementCert)
*/
	protectorPublic := new(rsa.PublicKey)
	protectorPublic.E = 0x00010001
	M := new(big.Int)
	M.SetBytes(endorseParams.Modulus)
	protectorPublic.N = M

	// MakeCredential
	// REMOVE: hash_alg_id := uint16(tpm2.AlgTPM_ALG_SHA1)
	encrypted_secret, encIdentity, integrityHmac, err := tpm2.MakeCredential(
		protectorPublic, uint16(tpm2.AlgTPM_ALG_SHA1), credential, name)
	if err != nil {
		t.Fatal("Can't MakeCredential\n")
	}

	// ActivateCredential
	recovered_credential2, err := tpm2.ActivateCredential(rw,
		key_handle, parent_handle, "", "",
		append(integrityHmac, encIdentity...), encrypted_secret)
	if err != nil {
		t.Fatal("Can't ActivateCredential\n")
	}
	if bytes.Compare(credential, recovered_credential2) != 0 {
		t.Fatal("Credential and recovered credential differ\n")
	}
	fmt.Printf("Make/Activate test succeeds\n")
}

func RestInternalSignProtocol(t *testing.T) {
return
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if (err != nil) {
		t.Fatal("Can't open tpm")
	}
	defer rw.Close()

	var notBefore time.Time
	notBefore = time.Now()
	validFor := 365*24*time.Hour
	notAfter := notBefore.Add(validFor)

	policyKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("Can't generate policy key\n")
	}
	derPolicyCert, err := tpm2.GenerateSelfSignedCertFromKey(policyKey,
		"Cloudproxy Authority", "Application Policy Key",
		tpm2.GetSerialNumber(), notBefore, notAfter)
	if err != nil {
		t.Fatal("Can't generate policy key\n")
	}
	fmt.Printf("policyKey: %x\n", policyKey)

	primaryHandle, _, err := tpm2.CreateEndorsement(rw, 2048, []int{7})
	if err != nil {
		t.Fatal("Can't CreateEndorsement")
	}
	derEndorsementCert, err := tpm2.GenerateHWCert(rw,
		primaryHandle, "JohnsHw", notBefore, notAfter,
		tpm2.GetSerialNumber(), derPolicyCert, policyKey)
	if err != nil {
		t.Fatal("Can't create endorsement cert")
	}
	fmt.Printf("Endorsement cert: %x\n", derEndorsementCert)
	// signing instructions
	signing_instructions_message := new(tpm2.SigningInstructionsMessage)
	issuer := "JLM CA"
	signing_instructions_message.Issuer = &issuer
	var duration int64
	duration = 86500*365
	signing_instructions_message.Duration = &duration
	purpose := "Signing"
	signing_instructions_message.Purpose = &purpose
	signalg := "RSA"
	hashalg := "sha1"
	signing_instructions_message.SignAlg = &signalg
	signing_instructions_message.HashAlg = &hashalg
	isCA := false
	canSign := true
	signing_instructions_message.IsCA = &isCA
	signing_instructions_message.CanSign = &canSign
	fmt.Printf("Got signing instructions\n")

	//
	// Cloudproxy protocol
	//

	pcrs := []int{7}
	quotePassword := "01020304"

	programName := "TestProgram"
	fmt.Printf("Program name is %s\n",  programName)

	// Client request.
	protoClientPrivateKey, request, err := tpm2.ConstructClientRequest(rw,
		derEndorsementCert, tpm2.Handle(tpm2.QuoteKeyHandle), "",
		quotePassword, programName)
	if err != nil {
		t.Fatal("ConstructClientRequest failed")
	}
	fmt.Printf("ConstructClientRequest succeeded\n")
	fmt.Printf("Key: %s\n", proto.CompactTextString(protoClientPrivateKey))
	fmt.Printf("Request: %s\n", proto.CompactTextString(request))
	fmt.Printf("Program name from request: %s\n\n", *request.ProgramKey.ProgramName)

	// Create Session for seal/unseal
	sessionHandle, policy_digest, err := tpm2.AssistCreateSession(rw,
		tpm2.AlgTPM_ALG_SHA1, pcrs)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("Can't start session for Seal")
	}
	fmt.Printf("Session handle: %x\n", sessionHandle)
	fmt.Printf("policy_digest: %x\n\n", policy_digest)
	defer tpm2.FlushContext(rw, sessionHandle)

	// Serialize the client private key proto, seal it and save it.
	var unsealing_secret [32]byte
	rand.Read(unsealing_secret[0:32])
	sealed_priv, sealed_pub, err := tpm2.AssistSeal(rw,
		tpm2.Handle(tpm2.RootKeyHandle), unsealing_secret[0:32],
		"", "", pcrs, policy_digest)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("Can't seal Program private key sealing secret")
	}
	serialized_program_key, err := proto.Marshal(protoClientPrivateKey)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("Can't marshal Program private key")
	}
	fmt.Printf("sealed priv, pub: %x %x\n\n", sealed_priv, sealed_pub)

	// Encrypt private key.
	var inHmac []byte
        calcHmac, encrypted_program_key, err := tpm2.EncryptDataWithCredential(
		true, tpm2.AlgTPM_ALG_SHA1, unsealing_secret[0:32],
		serialized_program_key, inHmac)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("Can't tpm2.EncryptDataWithCredential program key")
	}

	// Server response.
	response, err := tpm2.ConstructServerResponse(policyKey,
		derPolicyCert, *signing_instructions_message, *request)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("ConstructServerResponse failed")
	}
	if response == nil {
		t.Fatal("response is nil")
	}
	fmt.Printf("Response for ProgramName %s\n", *response.ProgramName)

	// Client cert recovery.
	endorsementHandle, _, err := tpm2.CreateEndorsement(rw, 2048, pcrs)
	if err != nil {
		t.Fatal("Can't CreateEndorsement")
	}
	cert, err := tpm2.ClientDecodeServerResponse(rw,
		endorsementHandle,
                tpm2.Handle(tpm2.QuoteKeyHandle),
		quotePassword, *response)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("ClientDecodeServerResponse failed")
	}
	fmt.Printf("cert: %x\n", cert)

	// Example: recover program private key from buffer.
	encryptedProgramKey := append(calcHmac, encrypted_program_key...)
	programPrivateBlob := sealed_priv
	programPublicBlob := sealed_pub
	recovered_hmac := encryptedProgramKey[0:20]
	recovered_cipher_text := encryptedProgramKey[20:len(encryptedProgramKey)]
	fmt.Printf("Recovered hmac, cipher_text: %x, %x\n", recovered_hmac,
		recovered_cipher_text)
	fmt.Printf("encryptedProgramKey: %x\n", encryptedProgramKey)
	fmt.Printf("Recovered priv, pub: %x, %x\n\n", programPrivateBlob,
		programPublicBlob)

	// Unseal secret and decrypt private policy key.
	unsealed, _, err := tpm2.AssistUnseal(rw, sessionHandle,
		tpm2.Handle(tpm2.RootKeyHandle), sealed_pub, sealed_priv,
		"", "", policy_digest)
        if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("Can't Unseal")
        }
        _, decrypted_program_key, err := tpm2.EncryptDataWithCredential(false,
		tpm2.AlgTPM_ALG_SHA1, unsealed, encrypted_program_key, calcHmac)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("Can't EncryptDataWithCredential (decrypt) program key")
	}
	fmt.Printf("unsealed: %x\n", unsealed)
	fmt.Printf("decrypted_program_key: %x\n\n", decrypted_program_key)

	// Close session.
	tpm2.FlushContext(rw, sessionHandle)

	fmt.Printf("Recovered Program keys: %x\n\n", decrypted_program_key)
	fmt.Printf("Cloudproxy protocol succeeds\n")
}

func RestSignProtocolChannel(t *testing.T) {
}

func RestPCR1718(t *testing.T) {
}



