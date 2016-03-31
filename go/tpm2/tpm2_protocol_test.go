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
	"crypto/rsa"
	"fmt"
        "testing"
	"time"

	"github.com/jlmucb/cloudproxy/go/tpm2"
)

func TestCreateKeyHierarchy(t *testing.T) {
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if (err != nil) {
		t.Fatal("Can't open tpm")
	}
	err = tpm2.CreateTpm2KeyHierarchy(rw, []int{7}, 2048, tpm2.AlgTPM_ALG_SHA1,
			tpm2.PrimaryKeyHandle, tpm2.QuoteKeyHandle, "01020304")
	if (err != nil) {
		t.Fatal("Can't create key hierarchy")
	}
	tpm2.Flushall(rw)
	rw.Close()
}

func TestMakeEndorsementCert(t *testing.T) {
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if (err != nil) {
		t.Fatal("Can't open tpm")
	}
	err = tpm2.CreateTpm2KeyHierarchy(rw, []int{7}, 2048, tpm2.AlgTPM_ALG_SHA1,
			tpm2.PrimaryKeyHandle, tpm2.QuoteKeyHandle, "01020304")
	if (err != nil) {
		t.Fatal("Can't create key hierarchy")
	}

	var notBefore time.Time
        notBefore = time.Now()
        validFor := 365*24*time.Hour
        notAfter := notBefore.Add(validFor)

	var derPolicyCert []byte
	var policyKey *rsa.PrivateKey
	endorsementCert, err := tpm2.GenerateHWCert(rw, tpm2.Handle(tpm2.PrimaryKeyHandle), "JohnsHw",
        	notBefore, notAfter, tpm2.GetSerialNumber(), derPolicyCert, policyKey)
	if err != nil {
		t.Fatal("Can't create endorsement cert")
	}
	fmt.Printf("Endorsement cert: %x\n", endorsementCert)
	tpm2.Flushall(rw)
	rw.Close()
}

func TestSeal(t *testing.T) {
}

func TestUnseal(t *testing.T) {
}

func TestAttest(t *testing.T) {
}

func TestSignAttest(t *testing.T) {
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if (err != nil) {
		t.Fatal("Can't open tpm")
	}
	err = tpm2.CreateTpm2KeyHierarchy(rw, []int{7}, 2048, tpm2.AlgTPM_ALG_SHA1,
			tpm2.PrimaryKeyHandle, tpm2.QuoteKeyHandle, "01020304")
	if (err != nil) {
		t.Fatal("Can't create key hierarchy")
	}

	var notBefore time.Time
        notBefore = time.Now()
        validFor := 365*24*time.Hour
        notAfter := notBefore.Add(validFor)

	var derPolicyCert []byte
	var policyKey *rsa.PrivateKey
	attestCert, err := tpm2.GenerateHWCert(rw, tpm2.Handle(tpm2.QuoteKeyHandle), "JohnsHw",
        	notBefore, notAfter, tpm2.GetSerialNumber(), derPolicyCert, policyKey)
	if err != nil {
		t.Fatal("Can't create attest cert")
	}
	fmt.Printf("Attest cert: %x\n", attestCert)
	tpm2.Flushall(rw)
	rw.Close()
}

func TestSignProtocol(t *testing.T) {
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if (err != nil) {
		t.Fatal("Can't open tpm")
	}
	err = tpm2.CreateTpm2KeyHierarchy(rw, []int{7}, 2048, tpm2.AlgTPM_ALG_SHA1,
			tpm2.PrimaryKeyHandle, tpm2.QuoteKeyHandle, "01020304")
	if (err != nil) {
		t.Fatal("Can't create key hierarchy")
	}

	/*
	var notBefore time.Time
        notBefore = time.Now()
        validFor := 365*24*time.Hour
        notAfter := notBefore.Add(validFor)

	var derPolicyCert []byte
	var policyKey *rsa.PrivateKey

	// Read Policy Cert
	derPolicyCert := tpm.RetrieveFile(*fileNamePolicyCert)
	if derPolicyCert == nil {
		fmt.Printf("Can't read policy cert\n")
		return
	}

	// Read Endorsement key info
	derEndorsementCert := tpm.RetrieveFile(*fileNameEndorsementCert)
	if derEndorsementCert == nil {
		fmt.Printf("Can't read endorsement cert\n")
		return
	}

	// Get endorsement public from cert
	endorsement_cert, err := x509.ParseCertificate(derEndorsementCert)
	if err != nil {
		fmt.Printf("Endorsement ParseCertificate fails\n")
		return
	}
	fmt.Printf("Endorsement cert: %x\n", derEndorsementCert)

	var protectorPublic *rsa.PublicKey
	switch k :=  endorsement_cert.PublicKey.(type) {
	case  *rsa.PublicKey:
		protectorPublic = k
	case  *rsa.PrivateKey:
		protectorPublic = &k.PublicKey
	default:
		fmt.Printf("endorsement cert is not an rsa key\n")
		return
	}
	fmt.Printf("Endorsement public: %x\n\n", protectorPublic)

	// Open tpm
	rw, err := tpm.OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}
	defer rw.Close()

	// CreatePrimary for Endorsement key
	var empty []byte
	primaryparms := tpm.RsaParams{uint16(tpm.AlgTPM_ALG_RSA),
		uint16(tpm.AlgTPM_ALG_SHA1), uint32(0x00030072), empty,
		uint16(tpm.AlgTPM_ALG_AES), uint16(128),
		uint16(tpm.AlgTPM_ALG_CFB), uint16(tpm.AlgTPM_ALG_NULL),
		uint16(0), 2048, uint32(0x00010001), empty}
	protectorHandle, _, err := tpm.CreatePrimary(rw,
		uint32(tpm.OrdTPM_RH_ENDORSEMENT), []int{0x7}, "", "", primaryparms)
	if err != nil {
		fmt.Printf("CreatePrimary fails")
		return
	}
	fmt.Printf("CreatePrimary succeeded\n")
	fmt.Printf("Endorsement handle: %x\n\n", protectorHandle)

	// Read Policy key
	protoPolicyKey := tpm.RetrieveFile(*fileNamePolicyKey)
	if protoPolicyKey == nil {
		fmt.Printf("Can't read policy key file\n")
		return
	}

	// Parse policy key
	keyMsg := new(tpm.RsaPrivateKeyMessage)
	err = proto.Unmarshal(protoPolicyKey, keyMsg)
	if err != nil {
		fmt.Printf("Can't unmarshal policy key\n")
		return
	}
	policyPrivateKey, err := tpm.UnmarshalRsaPrivateFromProto(keyMsg)
	if err != nil {
		fmt.Printf("Can't decode policy key\n")
		return
	}
	fmt.Printf("Key: %x\n", policyPrivateKey)

	// Read signing instructions
	signingInstructionsIn := tpm.RetrieveFile(*fileNameSigningInstructions)
	if signingInstructionsIn == nil {
		fmt.Printf("Can't read signing instructions\n")
		return
	}
	signing_instructions_message := new(tpm.SigningInstructionsMessage)
	err = proto.Unmarshal(signingInstructionsIn,
		signing_instructions_message)
	if  err != nil {
		fmt.Printf("Can't unmarshal signing instructions\n", err)
		return
	}
	fmt.Printf("Got signing instructions\n")

	//
	// Cloudproxy protocol
	//
	fmt.Printf("Program name is %s\n",  *programName)
	prog_name := *programName

	// Client request.
	protoClientPrivateKey, request, err := tpm.ConstructClientRequest(rw,
		derEndorsementCert, tpm.Handle(*permQuoteHandle), "",
		*quoteOwnerPassword, prog_name)
	if err != nil {
		fmt.Printf("ConstructClientRequest failed\n")
		return
	}
	fmt.Printf("ConstructClientRequest succeeded\n")
	fmt.Printf("Key: %s\n", proto.CompactTextString(protoClientPrivateKey))
	fmt.Printf("Request: %s\n", proto.CompactTextString(request))
	fmt.Printf("Program name from request: %s\n\n",
		*request.ProgramKey.ProgramName)

	// Create Session for seal/unseal
	sessionHandle, policy_digest, err := assistCreateSession(rw,
		tpm.AlgTPM_ALG_SHA1, []int{7})
	if err != nil {
		fmt.Printf("Can't start session for Seal\n")
		return
	}
	fmt.Printf("Session handle: %x\n", sessionHandle)
	fmt.Printf("policy_digest: %x\n\n", policy_digest)

	// Serialize the client private key proto, seal it and save it.
	var unsealing_secret [32]byte
	rand.Read(unsealing_secret[0:32])
	sealed_priv, sealed_pub, err := assistSeal(rw,
		tpm.Handle(*permPrimaryHandle), unsealing_secret[0:32],
		*sealedParentPassword, *sealedOwnerPassword,
		[]int{7}, policy_digest)
	if err != nil {
		fmt.Printf("Can't seal Program private key sealing secret\n")
		return
	}
	serialized_program_key, err := proto.Marshal(protoClientPrivateKey)
	if err != nil {
		fmt.Printf("Can't marshal Program private key\n")
		return
	}
	fmt.Printf("sealed priv, pub: %x %x\n\n", sealed_priv, sealed_pub)

	// Encrypt private key.
	var inHmac []byte
        calcHmac, encrypted_program_key, err := tpm.EncryptDataWithCredential(
		true, tpm.AlgTPM_ALG_SHA1, unsealing_secret[0:32],
		serialized_program_key, inHmac)
	if err != nil {
		fmt.Printf("Can't tpm.EncryptDataWithCredential program key\n")
		return
	}
	ioutil.WriteFile(*sealedProgramKeyFile +
		".encrypted_program_key",
		append(calcHmac, encrypted_program_key...), 0644)
	ioutil.WriteFile(*sealedProgramKeyFile + ".private", sealed_priv, 0644)
	ioutil.WriteFile(*sealedProgramKeyFile + ".public", sealed_pub, 0644)

	// Server response.
	response, err := tpm.ConstructServerResponse(policyPrivateKey,
		derPolicyCert, *signing_instructions_message, *request)
	if err != nil {
		fmt.Printf("ConstructServerResponse failed\n")
		return
	}
	if response == nil {
		fmt.Printf("response is nil\n")
		return
	}
	fmt.Printf("Response for ProgramName %s\n", *response.ProgramName)

	// Client cert recovery.
	cert, err := tpm.ClientDecodeServerResponse(rw, protectorHandle,
                tpm.Handle(*permQuoteHandle), *quoteOwnerPassword, *response)
	if err != nil {
		fmt.Printf("ClientDecodeServerResponse failed\n")
		return
	}

	// Example: recover program private key from buffer.
	encryptedProgramKey := tpm.RetrieveFile(*sealedProgramKeyFile +
		".encrypted_program_key")
	programPrivateBlob := tpm.RetrieveFile(*sealedProgramKeyFile +
		".private")
	programPublicBlob := tpm.RetrieveFile(*sealedProgramKeyFile + ".public")
	recovered_hmac := encryptedProgramKey[0:20]
	recovered_cipher_text := encryptedProgramKey[20:len(encryptedProgramKey)]
	fmt.Printf("Recovered hmac, cipher_text: %x, %x\n", recovered_hmac,
		recovered_cipher_text)
	fmt.Printf("encryptedProgramKey: %x\n", encryptedProgramKey)
	fmt.Printf("Recovered priv, pub: %x, %x\n\n", programPrivateBlob,
		programPublicBlob)

	// Unseal secret and decrypt private policy key.
	unsealed, _, err := assistUnseal(rw, sessionHandle,
		tpm.Handle(*permPrimaryHandle), sealed_pub, sealed_priv,
		"", *sealedOwnerPassword, policy_digest)
        if err != nil {
                fmt.Printf("Can't Unseal\n")
		return
        }
        _, decrypted_program_key, err := tpm.EncryptDataWithCredential(false,
		tpm.AlgTPM_ALG_SHA1, unsealed, encrypted_program_key, calcHmac)
	if err != nil {
		fmt.Printf("Can't EncryptDataWithCredential (decrypt) program key\n")
		return
	}
	fmt.Printf("unsealed: %x\n", unsealed)
	fmt.Printf("decrypted_program_key: %x\n\n", decrypted_program_key)

	// Close session.
	tpm.FlushContext(rw, sessionHandle)

	// Unmarshal private policy key.
	newPrivKeyMsg := new(tpm.RsaPrivateKeyMessage)
        err = proto.Unmarshal(decrypted_program_key, newPrivKeyMsg)
        newProgramKey, err := tpm.UnmarshalRsaPrivateFromProto(newPrivKeyMsg)
        if err != nil {
                fmt.Printf("Can't unmarshal key to proto\n")
		return
        }
	fmt.Printf("Recovered Program keys: %x\n\n", newProgramKey)
	fmt.Printf("Cloudproxy protocol succeeds\n")
	 */
}

func TestSignProtocolChannel(t *testing.T) {
}

func TestPCR1718(t *testing.T) {
}



