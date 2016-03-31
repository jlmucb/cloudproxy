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
	"crypto/rand"
	"fmt"
        "testing"
	"time"

	"github.com/jlmucb/cloudproxy/go/tpm2"
	"github.com/golang/protobuf/proto"
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

	// TODO
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

func TestInternalSignProtocol(t *testing.T) {
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

	policyKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("Can't generate policy key\n")
	}
	derPolicyCert, err := tpm2.GenerateSelfSignedCertFromKey(policyKey, "Cloudproxy Authority",
		"Application Policy Key", tpm2.GetSerialNumber(), notBefore, notAfter)
	if err != nil {
		t.Fatal("Can't generate policy key\n")
	}
	fmt.Printf("policyKey: %x\n", policyKey)

	derEndorsementCert, err := tpm2.GenerateHWCert(rw, tpm2.Handle(tpm2.PrimaryKeyHandle), "JohnsHw",
        	notBefore, notAfter, tpm2.GetSerialNumber(), derPolicyCert, policyKey)
	if err != nil {
		t.Fatal("Can't create endorsement cert")
	}

/*
	// Get endorsement public from cert
	endorsementCert, err := x509.ParseCertificate(derEndorsementCert)
	if err != nil {
		fmt.Printf("Endorsement ParseCertificate fails\n")
		return
	}
 */
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

	programName := "TestProgram"
	fmt.Printf("Program name is %s\n",  programName)

	// Client request.
	protoClientPrivateKey, request, err := tpm2.ConstructClientRequest(rw,
		derEndorsementCert, tpm2.Handle(tpm2.QuoteKeyHandle), "",
		"01020304", programName)
	if err != nil {
		fmt.Printf("ConstructClientRequest failed\n")
		return
	}
	fmt.Printf("ConstructClientRequest succeeded\n")
	fmt.Printf("Key: %s\n", proto.CompactTextString(protoClientPrivateKey))
	fmt.Printf("Request: %s\n", proto.CompactTextString(request))
	fmt.Printf("Program name from request: %s\n\n", *request.ProgramKey.ProgramName)

	// Create Session for seal/unseal
	sessionHandle, policy_digest, err := tpm2.AssistCreateSession(rw, tpm2.AlgTPM_ALG_SHA1, []int{7})
	if err != nil {
		fmt.Printf("Can't start session for Seal\n")
		return
	}
	fmt.Printf("Session handle: %x\n", sessionHandle)
	fmt.Printf("policy_digest: %x\n\n", policy_digest)

	// Serialize the client private key proto, seal it and save it.
	var unsealing_secret [32]byte
	rand.Read(unsealing_secret[0:32])
	sealed_priv, sealed_pub, err := tpm2.AssistSeal(rw,
		tpm2.Handle(tpm2.PrimaryKeyHandle), unsealing_secret[0:32],
		"", "01020304", []int{7}, policy_digest)
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
        calcHmac, encrypted_program_key, err := tpm2.EncryptDataWithCredential(
		true, tpm2.AlgTPM_ALG_SHA1, unsealing_secret[0:32],
		serialized_program_key, inHmac)
	if err != nil {
		fmt.Printf("Can't tpm2.EncryptDataWithCredential program key\n")
		return
	}

	// Server response.
	response, err := tpm2.ConstructServerResponse(policyKey,
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
	cert, err := tpm2.ClientDecodeServerResponse(rw, tpm2.Handle(tpm2.PrimaryKeyHandle),
                tpm2.Handle(tpm2.QuoteKeyHandle), "01020304", *response)
	if err != nil {
		fmt.Printf("ClientDecodeServerResponse failed\n")
		return
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
		tpm2.Handle(tpm2.PrimaryKeyHandle), sealed_pub, sealed_priv,
		"", "01020304", policy_digest)
        if err != nil {
                fmt.Printf("Can't Unseal\n")
		return
        }
        _, decrypted_program_key, err := tpm2.EncryptDataWithCredential(false,
		tpm2.AlgTPM_ALG_SHA1, unsealed, encrypted_program_key, calcHmac)
	if err != nil {
		fmt.Printf("Can't EncryptDataWithCredential (decrypt) program key\n")
		return
	}
	fmt.Printf("unsealed: %x\n", unsealed)
	fmt.Printf("decrypted_program_key: %x\n\n", decrypted_program_key)

	// Close session.
	tpm2.FlushContext(rw, sessionHandle)

	fmt.Printf("Recovered Program keys: %x\n\n", decrypted_program_key)
	fmt.Printf("Cloudproxy protocol succeeds\n")
	rw.Close()
}

func TestSignProtocolChannel(t *testing.T) {
}

func TestPCR1718(t *testing.T) {
}



