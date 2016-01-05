// Copyright (c) 2014, Google Inc. All rights reserved.
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

package tpm

import (
        "bytes"
        "fmt"
        "github.com/golang/protobuf/proto"
        "os"
        "testing"
)

// Test GetRandom
func TestEndian(t *testing.T) {
        l := uint16(0xff12)
        v := byte(l >> 8)
        var s [2]byte
        s[0] = v
        v = byte(l & 0xff)
        s[1] = v
        fmt.Printf("Endian test: %x\n", s)
}

// Test GetRandom
func TestGetRandom(t *testing.T) {
        fmt.Printf("TestGetRandom\n")

        // Open TPM
        rw, err := OpenTPM("/dev/tpm0")
        if err != nil {
                fmt.Printf("OpenTPM failed %s\n", err)
                return 
        }

        rand, err :=  GetRandom(rw, 16)
        if err != nil {
                fmt.Printf("Error: %s\n", err)
                t.Fatal("GetRandom failed\n")
        }
        fmt.Printf("rand: %x\n", rand)
        rw.Close()
}

// TestReadPcr tests a ReadPcr command.
func TestReadPcrs(t *testing.T) {
        fmt.Printf("TestReadPcrs\n")

        // Open TPM
        rw, err := OpenTPM("/dev/tpm0")
        if err != nil {
                fmt.Printf("OpenTPM failed %s\n", err)
                return 
        }

        pcr := []byte{0x03, 0x80, 0x00, 0x00}
        counter, pcr_out, alg, digest, err := ReadPcrs(rw, byte(4), pcr)
        if err != nil {
                t.Fatal("ReadPcrs failed\n")
        }
        fmt.Printf("Counter: %x, pcr: %x, alg: %x, digest: %x\n", counter, pcr_out, alg, digest)
        rw.Close()
}

// TestReadClock tests a ReadClock command.
func TestReadClock(t *testing.T) {
        fmt.Printf("TestReadClock\n")

        // Open TPM
        rw, err := OpenTPM("/dev/tpm0")
        if err != nil {
                fmt.Printf("OpenTPM failed %s\n", err)
                return 
        }
        current_time, current_clock, err := ReadClock(rw) 
        if err != nil {
                t.Fatal("ReadClock failed\n")
        }
        fmt.Printf("current_time: %x , current_clock: %x\n", current_time, current_clock)
        rw.Close()

}

// TestGetCapabilities tests a GetCapabilities command.
// Command: 8001000000160000017a000000018000000000000014
func TestGetCapabilities(t *testing.T) {

        // Open TPM
        rw, err := OpenTPM("/dev/tpm0")
        if err != nil {
                fmt.Printf("OpenTPM failed %s\n", err)
                return 
        }
        handles, err := GetCapabilities(rw, ordTPM_CAP_HANDLES, 1, 0x80000000)
        if err != nil {
                t.Fatal("GetCapabilities failed\n")
        }
        fmt.Printf("Open handles:\n")
        for _, e := range handles {
                fmt.Printf("    %x\n", e)
        }
        rw.Close()
}

// Combined Key Test
func TestCombinedKeyTest(t *testing.T) {

        // Open tpm
        rw, err := OpenTPM("/dev/tpm0")
        if err != nil {
                fmt.Printf("OpenTPM failed %s\n", err)
                return 
        }

        // Flushall
        err =  Flushall(rw)
        if err != nil {
                t.Fatal("Flushall failed\n")
        }
        fmt.Printf("Flushall succeeded\n")

        // CreatePrimary
        var empty []byte
        primaryparms := RsaParams{uint16(algTPM_ALG_RSA), uint16(algTPM_ALG_SHA1),
                uint32(0x00030072), empty, uint16(algTPM_ALG_AES), uint16(128),
                uint16(algTPM_ALG_CFB), uint16(algTPM_ALG_NULL), uint16(0),
                uint16(1024), uint32(0x00010001), empty}
        parent_handle, public_blob, err := CreatePrimary(rw,
                uint32(ordTPM_RH_OWNER), []int{0x7}, "", "01020304", primaryparms)
        if err != nil {
                t.Fatal("CreatePrimary fails")
        }
        fmt.Printf("CreatePrimary succeeded\n")

        // CreateKey
        keyparms := RsaParams{uint16(algTPM_ALG_RSA), uint16(algTPM_ALG_SHA1),
                uint32(0x00030072), empty, uint16(algTPM_ALG_AES), uint16(128),
                uint16(algTPM_ALG_CFB), uint16(algTPM_ALG_NULL), uint16(0),
                uint16(1024), uint32(0x00010001), empty}
        private_blob, public_blob, err := CreateKey(rw, uint32(parent_handle), 
                []int{7}, "01020304", "01020304", keyparms)
        if err != nil {
                t.Fatal("CreateKey fails")
        }
        fmt.Printf("CreateKey succeeded, handle: %x\n", uint32(parent_handle))
        fmt.Printf("Private blob: %x\n", private_blob)
        fmt.Printf("Public  blob: %x\n\n", public_blob)

        // Load
        key_handle, blob, err := Load(rw, parent_handle, "", "01020304",
             public_blob, private_blob)
        if err != nil {
                t.Fatal("Load fails")
        }
        fmt.Printf("Load succeeded, handle: %x\n", uint32(key_handle))
        fmt.Printf("Blob from Load     : %x\n", blob)

        // ReadPublic
        public, name, qualified_name, err := ReadPublic(rw, key_handle)
        if err != nil {
                t.Fatal("ReadPublic fails")
        }
        fmt.Printf("ReadPublic succeeded\n")
        fmt.Printf("Public         blob: %x\n", public)
        fmt.Printf("Name           blob: %x\n", name)
        fmt.Printf("Qualified name blob: %x\n\n", qualified_name)

        // Flush
        err = FlushContext(rw, key_handle)
        err = FlushContext(rw, parent_handle)
        rw.Close()
}

// Combined Seal test
func TestCombinedSealTest(t *testing.T) {

        // Open tpm
        rw, err := OpenTPM("/dev/tpm0")
        if err != nil {
                fmt.Printf("OpenTPM failed %s\n", err)
                return 
        }

        // Flushall
        err =  Flushall(rw)
        if err != nil {
                t.Fatal("Flushall failed\n")
        }
        fmt.Printf("Flushall succeeded\n")

        // CreatePrimary
        var empty []byte
        primaryparms := RsaParams{uint16(algTPM_ALG_RSA), uint16(algTPM_ALG_SHA1),
                uint32(0x00030072), empty, uint16(algTPM_ALG_AES), uint16(128),
                uint16(algTPM_ALG_CFB), uint16(algTPM_ALG_NULL), uint16(0),
                uint16(1024), uint32(0x00010001), empty}
        parent_handle, public_blob, err := CreatePrimary(rw,
                uint32(ordTPM_RH_OWNER), []int{0x7}, "", "01020304", primaryparms)
        if err != nil {
                t.Fatal("CreatePrimary fails")
        }
        fmt.Printf("CreatePrimary succeeded\n")

        nonceCaller := []byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
        var secret []byte
        sym := uint16(algTPM_ALG_NULL)
        to_seal := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
        hash_alg := uint16(algTPM_ALG_SHA1)

        session_handle, policy_digest, err := StartAuthSession(rw, Handle(ordTPM_RH_NULL),
                Handle(ordTPM_RH_NULL), nonceCaller, secret,
                uint8(ordTPM_SE_POLICY), sym, hash_alg)
        if err != nil {
		FlushContext(rw, parent_handle)
                t.Fatal("StartAuthSession fails")
        }
        fmt.Printf("StartAuth succeeds, handle: %x\n", uint32(session_handle))
        fmt.Printf("policy digest  : %x\n", policy_digest)

	var tmp_digest []byte
        err = PolicyPcr(rw, session_handle, tmp_digest, []int{7})
        if err != nil {
		FlushContext(rw, parent_handle)
		FlushContext(rw, session_handle)
                t.Fatal("PolicyPcr fails")
        }
        policy_digest, err = PolicyGetDigest(rw, session_handle)
        if err != nil {
		FlushContext(rw, parent_handle)
		FlushContext(rw, session_handle)
                t.Fatal("PolicyGetDigest after PolicyPcr fails")
        }
        fmt.Printf("policy digest after PolicyPcr: %x\n", policy_digest)

	// CreateSealed
        keyedhashparms := KeyedHashParams{uint16(algTPM_ALG_KEYEDHASH),
                uint16(algTPM_ALG_SHA1),
                uint32(0x00000012), empty, uint16(algTPM_ALG_AES), uint16(128),
                uint16(algTPM_ALG_CFB), uint16(algTPM_ALG_NULL), empty}
        private_blob, public_blob, err := CreateSealed(rw, parent_handle, policy_digest,
                "01020304",  "01020304", to_seal, []int{7}, keyedhashparms)
        if err != nil {
		FlushContext(rw, parent_handle)
		FlushContext(rw, session_handle)
                t.Fatal("CreateSealed fails")
        }

        // Load
        item_handle, blob, err := Load(rw, parent_handle, "", "01020304",
             	public_blob, private_blob)
        if err != nil {
		FlushContext(rw, session_handle)
		FlushContext(rw, item_handle)
		FlushContext(rw, parent_handle)
                t.Fatal("Load fails")
        }
        fmt.Printf("Load succeeded, handle: %x\n", uint32(item_handle))
        fmt.Printf("Blob from Load     : %x\n\n", blob)

        // Unseal
        unsealed, nonce, err := Unseal(rw, item_handle, "01020304", session_handle, policy_digest)
        if err != nil {
		FlushContext(rw, item_handle)
		FlushContext(rw, parent_handle)
                t.Fatal("Unseal fails")
        }
        fmt.Printf("Unseal succeeds\n")
        fmt.Printf("unsealed           : %x\n", unsealed)
        fmt.Printf("nonce              : %x\n\n", nonce)

        // Flush
        FlushContext(rw, item_handle)
        FlushContext(rw, parent_handle)
        FlushContext(rw, session_handle)
        rw.Close()
}

// Combined Quote test
func TestCombinedQuoteTest(t *testing.T) {
        fmt.Printf("TestCombinedQuoteTest excluded\n")
        return

        // Open tpm
        rw, err := OpenTPM("/dev/tpm0")
        if err != nil {
                fmt.Printf("OpenTPM failed %s\n", err)
                return 
        }

        // Flushall
        err =  Flushall(rw)
        if err != nil {
                t.Fatal("Flushall failed\n")
        }
        fmt.Printf("Flushall succeeded\n\n")

        // CreatePrimary
        var empty []byte
        primaryparms := RsaParams{uint16(algTPM_ALG_RSA), uint16(algTPM_ALG_SHA1),
                uint32(0x00030072), empty, uint16(algTPM_ALG_AES), uint16(128),
                uint16(algTPM_ALG_CFB), uint16(algTPM_ALG_NULL), uint16(0),
                uint16(1024), uint32(0x00010001), empty}
        parent_handle, public_blob, err := CreatePrimary(rw,
                uint32(ordTPM_RH_OWNER), []int{0x7}, "", "01020304", primaryparms)
        if err != nil {
                t.Fatal("CreatePrimary fails")
        }
        fmt.Printf("CreatePrimary succeeded\n\n")

	// Pcr event
	eventData := []byte{1,2,3}
	err =  PcrEvent(rw, 7, eventData)
        if err != nil {
                t.Fatal("PcrEvent fails")
        }

        // CreateKey (Quote Key)
        keyparms := RsaParams{uint16(algTPM_ALG_RSA), uint16(algTPM_ALG_SHA1),
                uint32(0x00030072), empty, uint16(algTPM_ALG_AES), uint16(128),
                uint16(algTPM_ALG_CFB), uint16(algTPM_ALG_NULL), uint16(0),
                uint16(1024), uint32(0x00010001), empty}
        private_blob, public_blob, err := CreateKey(rw, uint32(parent_handle), 
                []int{7}, "01020304", "01020304", keyparms)
        if err != nil {
                t.Fatal("CreateKey fails")
        }
        fmt.Printf("CreateKey succeeded\n")
        fmt.Printf("Private blob: %x\n", private_blob)
        fmt.Printf("Public  blob: %x\n", public_blob)

        // Load
        quote_handle, blob, err := Load(rw, parent_handle, "", "01020304",
             public_blob, private_blob)
        if err != nil {
                t.Fatal("Load fails")
        }
        fmt.Printf("Load succeeded, handle: %x\n", uint32(quote_handle))
        fmt.Printf("Blob from Load     : %x\n\n", blob)

        // Quote
        to_quote := []byte{0x0f,0x0e,0x0d,0x0c,0x0b,0x0a,0x09,0x08,
			   0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00}
        attest, sig, err := Quote(rw, quote_handle, "01020304", "01020304",
                to_quote, []int{7}, uint16(algTPM_ALG_RSA))
        if err != nil {
                t.Fatal("Quote fails")
        }
        fmt.Printf("attest             : %x\n", attest)
        fmt.Printf("sig                : %x\n\n", sig)

        // Verify quote
	var quote_key_info QuoteKeyInfoMessage // Fix
        if !VerifyQuote(to_quote, quote_key_info, uint16(algTPM_ALG_SHA1), attest, sig) {
                t.Fatal("VerifyQuote fails")
        }

        // Flush
        err = FlushContext(rw, quote_handle)
        err = FlushContext(rw, parent_handle)
        rw.Close()
}

// Combined Endorsement/Activate test
func TestCombinedEndorsementTest(t *testing.T) {
        fmt.Printf("TestCombinedEndorsementTest excluded\n")
        return

        hash_alg_id := uint16(algTPM_ALG_SHA1)

        // Open tpm
        rw, err := OpenTPM("/dev/tpm0")
        if err != nil {
                fmt.Printf("OpenTPM failed %s\n", err)
                return 
        }

        // Flushall
        err =  Flushall(rw)
        if err != nil {
                t.Fatal("Flushall failed\n")
        }
        fmt.Printf("Flushall succeeded\n\n")

        // CreatePrimary
        var empty []byte
        primaryparms := RsaParams{uint16(algTPM_ALG_RSA), uint16(algTPM_ALG_SHA1),
                uint32(0x00030072), empty, uint16(algTPM_ALG_AES), uint16(128),
                uint16(algTPM_ALG_CFB), uint16(algTPM_ALG_NULL), uint16(0),
                uint16(1024), uint32(0x00010001), empty}
        parent_handle, public_blob, err := CreatePrimary(rw,
                uint32(ordTPM_RH_OWNER), []int{0x7}, "", "01020304", primaryparms)
        if err != nil {
                t.Fatal("CreatePrimary fails")
        }
        fmt.Printf("CreatePrimary succeeded\n\n")

        // CreateKey
        keyparms := RsaParams{uint16(algTPM_ALG_RSA), uint16(algTPM_ALG_SHA1),
                uint32(0x00030072), empty, uint16(algTPM_ALG_AES), uint16(128),
                uint16(algTPM_ALG_CFB), uint16(algTPM_ALG_NULL), uint16(0),
                uint16(1024), uint32(0x00010001), empty}
        private_blob, public_blob, err := CreateKey(rw, uint32(parent_handle), 
                []int{7}, "01020304", "01020304", keyparms)
        if err != nil {
                t.Fatal("CreateKey fails")
        }
        fmt.Printf("CreateKey succeeded\n")
        fmt.Printf("Private blob: %x\n", private_blob)
        fmt.Printf("Public  blob: %x\n\n", public_blob)

        // Load
        key_handle, blob, err := Load(rw, parent_handle, "", "01020304",
             public_blob, private_blob)
        if err != nil {
                t.Fatal("Load fails")
        }
        fmt.Printf("Load succeeded\n")
        fmt.Printf("\nBlob from Load     : %x\n", blob)

        // ReadPublic
        public, name, qualified_name, err := ReadPublic(rw, key_handle)
        if err != nil {
                t.Fatal("ReadPublic fails")
        }
        fmt.Printf("ReadPublic succeeded\n")
        fmt.Printf("Public         blob: %x\n", public)
        fmt.Printf("Name           blob: %x\n", name)
        fmt.Printf("Qualified name blob: %x\n\n", qualified_name)

        // Get endorsement cert
        endorsement_cert_file := "/Users/jlm/cryptobin/endorsement_cert"
        fileInfo, err := os.Stat(endorsement_cert_file)
        if err != nil {
                t.Fatal("Can't stat endorsement cert file")
        }
        der_endorsement_cert := make([]byte, fileInfo.Size())
        cert_file, err := os.Open(endorsement_cert_file)
        if err != nil {
                t.Fatal("Can't open endorsement cert file")
        }
        _, err = cert_file.Read(der_endorsement_cert)
        if err != nil {
                cert_file.Close()
                t.Fatal("Can't read endorsement cert file")
        }
        cert_file.Close()

        // MakeCredential
        credential := []byte{1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf,0x10}
        fmt.Printf("Credential: %x\n", credential)

        encrypted_secret, encIdentity, integrityHmac, err := MakeCredential(
                der_endorsement_cert, hash_alg_id, credential[0:16], name)
        if err != nil {
                t.Fatal("Can't MakeCredential\n")
        }

        // ActivateCredential
        recovered_credential, err := ActivateCredential(rw, key_handle,
                parent_handle, "01020304",
                append(integrityHmac, encIdentity...), encrypted_secret)
        if err != nil {
                t.Fatal("Can't ActivateCredential\n")
        }
        fmt.Printf("Restored Credential: %x\n", recovered_credential)
        if bytes.Compare(credential, recovered_credential) != 0 {
                t.Fatal("Credential and recovered credential differ\n")
        }

        // Flush
        err = FlushContext(rw, key_handle)
        err = FlushContext(rw, parent_handle)
        rw.Close()
}

// Combined Evict test
func TestCombinedEvictTest(t *testing.T) {
        fmt.Printf("TestCombinedEvictTest excluded\n")
        return

        // Open tpm
        rw, err := OpenTPM("/dev/tpm0")
        if err != nil {
                fmt.Printf("OpenTPM failed %s\n", err)
                return 
        }

        // Flushall
        err =  Flushall(rw)
        if err != nil {
                t.Fatal("Flushall failed\n")
        }
        fmt.Printf("Flushall succeeded\n")

        // CreatePrimary
        var empty []byte
        primaryparms := RsaParams{uint16(algTPM_ALG_RSA), uint16(algTPM_ALG_SHA1),
                uint32(0x00030072), empty, uint16(algTPM_ALG_AES), uint16(128),
                uint16(algTPM_ALG_CFB), uint16(algTPM_ALG_NULL), uint16(0),
                uint16(1024), uint32(0x00010001), empty}
        parent_handle, public_blob, err := CreatePrimary(rw,
                uint32(ordTPM_RH_OWNER), []int{0x7}, "", "01020304", primaryparms)
        if err != nil {
                t.Fatal("CreatePrimary fails")
        }
        fmt.Printf("CreatePrimary succeeded\n")

        // CreateKey
        keyparms := RsaParams{uint16(algTPM_ALG_RSA), uint16(algTPM_ALG_SHA1),
                uint32(0x00030072), empty, uint16(algTPM_ALG_AES), uint16(128),
                uint16(algTPM_ALG_CFB), uint16(algTPM_ALG_NULL), uint16(0),
                uint16(1024), uint32(0x00010001), empty}
        private_blob, public_blob, err := CreateKey(rw, uint32(parent_handle), 
                []int{7}, "01020304", "01020304", keyparms)
        if err != nil {
                t.Fatal("CreateKey fails")
        }
        fmt.Printf("CreateKey succeeded\n")
        fmt.Printf("Private blob: %x\n", private_blob)
        fmt.Printf("Public  blob: %x\n\n", public_blob)

        // Load
        key_handle, blob, err := Load(rw, parent_handle, "", "01020304",
             public_blob, private_blob)
        if err != nil {
                t.Fatal("Load fails")
        }
        fmt.Printf("Load succeeded\n")
        fmt.Printf("\nBlob from Load     : %x\n", blob)

        // ReadPublic
        public, name, qualified_name, err := ReadPublic(rw, key_handle)
        if err != nil {
                t.Fatal("ReadPublic fails")
        }
        fmt.Printf("ReadPublic succeeded\n")
        fmt.Printf("Public         blob: %x\n", public)
        fmt.Printf("Name           blob: %x\n", name)
        fmt.Printf("Qualified name blob: %x\n\n", qualified_name)

        perm_handle := uint32(0x810003e8)

        // Evict
        err = EvictControl(rw, Handle(ordTPM_RH_OWNER), key_handle, "", "01020304",
                Handle(perm_handle))
        if err != nil {
                t.Fatal("EvictControl 1 fails")
        }

        // Evict
        err = EvictControl(rw, Handle(ordTPM_RH_OWNER), Handle(perm_handle), "", "01020304",
                Handle(perm_handle))
        if err != nil {
                t.Fatal("EvictControl 1 fails")
        }

        // Flush
        err = FlushContext(rw, key_handle)
        err = FlushContext(rw, parent_handle)
        rw.Close()
}

// Combined Context test
func TestCombinedContextTest(t *testing.T) {
        fmt.Printf("TestCombinedContextTest excluded\n")
        return
        // pcr selections
        // CreatePrimary
        // SaveContext
        // FlushContext
        // LoadContext
        // FlushContext
}

// Combined Quote Protocol
func TestCombinedQuoteProtocolTest(t *testing.T) {
        fmt.Printf("TestCombinedQuoteProtocolTest excluded\n")
        return

        // Read der-encoded private policy key
        private_key_file := "/Users/jlm/cryptobin/cloudproxy_key_file"
        fileInfo, err := os.Stat(private_key_file)
        if err != nil {
                t.Fatal("Can't stat private key file")
        }
        der_policy_key := make([]byte, fileInfo.Size())
        key_file, err := os.Open(private_key_file)
        if err != nil {
                t.Fatal("Can't open private key file")
        }
        _, err = key_file.Read(der_policy_key)
        if err != nil {
                key_file.Close()
                t.Fatal("Can't read private key file")
        }
        key_file.Close()

        // Read der-encoded policy cert
        policy_cert_file_name := "/Users/jlm/cryptobin/policy_key_cert"
        fileInfo, err = os.Stat(policy_cert_file_name)
        if err != nil {
                t.Fatal("Can't stat policy cert file")
        }
        der_policy_cert := make([]byte, fileInfo.Size())
        policy_cert_file, err := os.Open(policy_cert_file_name)
        if err != nil {
                t.Fatal("Can't open policy cert file")
        }
        _, err = policy_cert_file.Read(der_policy_cert)
        if err != nil {
                policy_cert_file.Close()
                t.Fatal("Can't read policy cert file")
        }
        policy_cert_file.Close()

        // Read endorsement cert file
        endorsement_cert_file := "/Users/jlm/cryptobin/endorsement_cert"
        fileInfo, err = os.Stat(endorsement_cert_file)
        if err != nil {
                t.Fatal("Can't stat endorsement cert file")
        }
        der_endorsement_cert := make([]byte, fileInfo.Size())
        cert_file, err := os.Open(private_key_file)
        if err != nil {
                t.Fatal("Can't open endorsement cert file")
        }
        _, err = cert_file.Read(der_endorsement_cert)
        if err != nil {
                cert_file.Close()
                t.Fatal("Can't read private key file")
        }
        cert_file.Close()
	fmt.Printf("Got endorsement cert: %x\n\n", der_endorsement_cert)

        // Open tpm
        rw, err := OpenTPM("/dev/tpm0")
        if err != nil {
                t.Fatal("Can't open tpm")
        }

        // Open endorsement and quote keys
        var empty []byte
        ek_parms := RsaParams{uint16(algTPM_ALG_RSA), uint16(algTPM_ALG_SHA1),
                uint32(0x00030072), empty, uint16(algTPM_ALG_AES), uint16(128),
                uint16(algTPM_ALG_CFB), uint16(algTPM_ALG_NULL), uint16(0),
                uint16(1024), uint32(0x00010001), empty}
        endorsement_handle, _, err := CreatePrimary(rw, uint32(ordTPM_RH_OWNER), []int{7},
                "", "01020304", ek_parms)
        if err != nil {
                t.Fatal("CreatePrimary fails")
        }
        quote_parms := RsaParams{uint16(algTPM_ALG_RSA), uint16(algTPM_ALG_SHA1),
                uint32(0x00030072), empty, uint16(algTPM_ALG_AES), uint16(128),
                uint16(algTPM_ALG_CFB), uint16(algTPM_ALG_NULL), uint16(0),
                uint16(1024), uint32(0x00010001), empty}
        private_blob, public_blob, err := CreateKey(rw, uint32(ordTPM_RH_OWNER), []int{7},
                                                    "", "01020304", quote_parms)
        if err != nil {
                t.Fatal("Create fails")
        }
	fmt.Printf("Create Key for quote succeeded\n")
	fmt.Printf("Private: %x\n", private_blob)
	fmt.Printf("Public: %x\n", public_blob)

        quote_handle, quote_blob, err := Load(rw, endorsement_handle, "", "01020304",
		public_blob, private_blob)
        if err != nil {
                t.Fatal("Quote Load fails")
        }
        fmt.Printf("Load succeeded, blob size: %d\n\n", len(quote_blob))

        der_program_private, request_message, err := ConstructClientRequest(rw, der_endorsement_cert,
                quote_handle, "", "01020304", "Test-Program-1")
        if err != nil {
                t.Fatal("ConstructClientRequest fails")
        }
        fmt.Printf("der_program_private size: %d\n", len(der_program_private))
        fmt.Printf("Request: %s\n", proto.MarshalTextString(request_message))

        signing_instructions_message := new(SigningInstructionsMessage)
        response_message, err := ConstructServerResponse(der_policy_cert,
		der_policy_key, *signing_instructions_message, *request_message)
        if err != nil {
                t.Fatal("ConstructServerResponse fails")
        }

        der_program_cert, err := ClientDecodeServerResponse(rw, endorsement_handle, quote_handle,
                "01020304", *response_message)
        if err != nil {
                t.Fatal("ClientDecodeServerResponse fails")
        }

        // Save Program cert
        fmt.Printf("Program cert: %x\n", der_program_cert)

        // Close handles
        FlushContext(rw, endorsement_handle)
        FlushContext(rw, quote_handle)
}
