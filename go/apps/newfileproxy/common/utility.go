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
// File: utility.go

package fileproxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"os"
	"path"

	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

// The size of a symmetric key is the size of an AES key plus the size of an
// HMAC key.
const SymmetricKeySize = 64

// A ProgramPolicy object represents the current domain policy of a program.
type ProgramPolicy struct {
	TaoName     string
	PolicyCert  []byte
	SigningKey  *tao.Keys
	SymKeys     []byte
	ProgramCert []byte
}

// NewProgramPolicy creates a new ProgramPolicy for a given set of keys.
func NewProgramPolicy(policyCert []byte, taoName string, signingKey *tao.Keys, symKeys []byte, programCert []byte) *ProgramPolicy {
	pp := &ProgramPolicy{
		PolicyCert:  policyCert,
		TaoName:     taoName,
		SigningKey:  signingKey,
		SymKeys:     symKeys,
		ProgramCert: programCert,
	}
	return pp
}

// EstablishCert contacts a CA to get a certificate signed by the policy key. It
// replaces the current delegation and cert on k with the new delegation and
// cert from the response.
func EstablishCert(network, addr string, k *tao.Keys, v *tao.Verifier) error {
	na, err := tao.RequestAttestation(network, addr, k, v)
	if err != nil {
		return err
	}

	k.Delegation = na
	pa, err := auth.UnmarshalForm(na.SerializedStatement)
	if err != nil {
		return err
	}

	// Parse the received statement.
	var saysStatement *auth.Says
	if ptr, ok := pa.(*auth.Says); ok {
		saysStatement = ptr
	} else if val, ok := pa.(auth.Says); ok {
		saysStatement = &val
	}
	sf, ok := saysStatement.Message.(auth.Speaksfor)
	if ok != true {
		return errors.New("says doesn't have speaksfor message")
	}

	kprin, ok := sf.Delegate.(auth.Term)
	if ok != true {
		return errors.New("speaksfor message doesn't have Delegate")
	}
	newCert := auth.Bytes(kprin.(auth.Bytes))
	k.Cert, err = x509.ParseCertificate(newCert)
	if err != nil {
		return err
	}

	return nil
}

const bufferSize = 2048
const ivSize = 16
const hmacKeySize = 16
const aesKeySize = 16
const minKeySize = hmacKeySize + aesKeySize

// SendFile reads a file from disk and streams it to a receiver across a
// MessageStream. If there are sufficient bytes in the keys (at least
// hmacKeySize+aesKeySize), then it will attempt to check the integrity of the
// file with HMAC-SHA256 and decrypt it with AES-CTR-128.
func SendFile(ms *util.MessageStream, dir string, filename string, keys []byte) error {
	fullpath := path.Join(dir, filename)
	fileInfo, err := os.Stat(fullpath)
	if err != nil {
		return fmt.Errorf("in SendFile: no file '%s' found: %s", fullpath, err)
	}
	file, err := os.Open(fullpath)
	if err != nil {
		return fmt.Errorf("in SendFile: can't open file '%s': %s", fullpath, err)
	}
	defer file.Close()

	// This encryption scheme uses AES-CTR with HMAC-SHA256 for integrity
	// protection.
	var hm hash.Hash
	var ctr cipher.Stream
	iv := make([]byte, ivSize)
	hasKeys := len(keys) >= minKeySize

	// The variable "left" gives the total number of bytes left to read from
	// the (maybe encrypted) file.
	left := fileInfo.Size()
	buf := make([]byte, bufferSize)
	if hasKeys {
		dec, err := aes.NewCipher(keys[:aesKeySize])
		if err != nil || dec == nil {
			return fmt.Errorf("can't create AES cipher in SendFile: %s", err)
		}
		if _, err := file.Read(iv); err != nil {
			return err
		}
		// Remove the IV from the number of remaining bytes to decrypt.
		left = left - ivSize

		// Take all the remaining key bytes for the HMAC key.
		hm = hmac.New(sha256.New, keys[aesKeySize:])
		hmacSize := hm.Size()

		// The HMAC input starts with the IV.
		hm.Write(iv)

		ctr = cipher.NewCTR(dec, iv)
		if ctr == nil {
			return fmt.Errorf("can't create AES-CTR encryption")
		}

		// Remove the HMAC-SHA256 output from the bytes to check.
		left = left - int64(hmacSize)

		// Secure decryption in this case requires reading the file
		// twice: once to check the MAC, and once to decrypt the bytes.
		// The MAC must be checked before *any* decryption occurs and
		// before *any* decrypted bytes are sent to the receiver.
		for {
			// Figure out how many bytes to read on this iteration.
			readSize := int64(bufferSize)
			final := false
			if left <= bufferSize {
				readSize = left
				final = true
			}

			// Read the (maybe encrypted) bytes from the file.
			n, err := file.Read(buf[:readSize])
			if err != nil {
				return err
			}
			left = left - int64(n)
			hm.Write(buf[:n])
			if final {
				break
			}
		}
		computed := hm.Sum(nil)
		original := buf[:hmacSize]

		// Read the file's version of the HMAC and check it securely
		// against the computed version.
		if _, err := file.Read(original); err != nil {
			return err
		}
		if !hmac.Equal(computed, original) {
			return fmt.Errorf("invalid file HMAC on decryption for file '%s'", fullpath)
		}

		// Go back to the beginning of the file (minus the IV) for
		// decryption.
		if _, err := file.Seek(ivSize, 0); err != nil {
			return fmt.Errorf("couldn't seek back to the beginning of file '%s': %s", fullpath, err)
		}

		// Reset the number of bytes so it only includes the encrypted
		// bytes.
		left = fileInfo.Size() - int64(ivSize+hmacSize)
	}

	// The input buffer, and a temporary buffer for holding decrypted
	// plaintext.
	temp := make([]byte, bufferSize)

	// Set up a framing message to use to send the data.
	m := &Message{
		Type: MessageType_FILE_NEXT.Enum(),
	}

	// Now that the integrity of the data has been verified, if needed, send
	// the data (after decryption, if necessary) to the receiver.
	for {
		// Figure out how many bytes to read on this iteration.
		readSize := int64(bufferSize)
		final := false
		if left <= bufferSize {
			readSize = left
			final = true
			m.Type = MessageType_FILE_LAST.Enum()
		}

		// Read the (maybe encrypted) bytes from the file.
		n, err := file.Read(buf[:readSize])
		if err != nil {
			return err
		}
		left = left - int64(n)

		if hasKeys {
			ctr.XORKeyStream(temp[:n], buf[:n])
			m.Data = temp[:n]
		} else {
			m.Data = buf[:n]
		}

		// Send the decrypted data to the receiver.
		if _, err := ms.WriteMessage(m); err != nil {
			return err
		}
		if final {
			break
		}
	}
	return nil
}

// GetFile receives bytes from a sender and optionally encrypts them and adds
// integrity protection, and writes them to disk.
func GetFile(ms *util.MessageStream, dir string, filename string, keys []byte) error {
	fullpath := path.Join(dir, filename)
	file, err := os.Create(fullpath)
	if err != nil {
		return fmt.Errorf("can't create file '%s' in GetFile", fullpath)
	}
	defer file.Close()

	var ctr cipher.Stream
	var hm hash.Hash
	iv := make([]byte, ivSize)

	hasKeys := len(keys) >= minKeySize
	if hasKeys {
		enc, err := aes.NewCipher(keys[:aesKeySize])
		if err != nil || enc == nil {
			return fmt.Errorf("couldn't create an AES cipher: %s", err)
		}

		// Use the remaining bytes of the key slice for the HMAC key.
		hm = hmac.New(sha256.New, keys[aesKeySize:])
		if _, err := rand.Read(iv); err != nil {
			return fmt.Errorf("couldn't read random bytes for a fresh IV: %s", err)
		}

		// The first bytes of the HMAC input are the IV.
		hm.Write(iv)
		ctr = cipher.NewCTR(enc, iv)
		if ctr == nil {
			return fmt.Errorf("couldn't create a new instance of AES-CTR-128")
		}
		if _, err = file.Write(iv); err != nil {
			return err
		}
	}

	// temp holds temporary encrypted ciphertext before it's written to
	// disk.
	temp := make([]byte, bufferSize)
	for {
		var m Message
		if err := ms.ReadMessage(&m); err != nil {
			return nil
		}

		// Sanity check: this must be FILE_LAST or FILE_NEXT.
		t := *m.Type
		if !(t == MessageType_FILE_LAST || t == MessageType_FILE_NEXT) {
			return fmt.Errorf("received invalid message type %d during file streaming in GetFile", t)
		}

		if hasKeys {
			l := len(m.Data)
			ctr.XORKeyStream(temp, m.Data)
			hm.Write(temp[:l])
			if _, err = file.Write(temp[:l]); err != nil {
				return err
			}
		} else {
			if _, err = file.Write(m.Data); err != nil {
				return err
			}
		}

		// FILE_LAST corresponds to receiving the final bytes of the
		// file.
		if *m.Type == MessageType_FILE_LAST {
			break
		}
	}

	// Write the MAC at the end of the file.
	if hasKeys {
		hmacBytes := hm.Sum(nil)
		if _, err = file.Write(hmacBytes[:]); err != nil {
			return err
		}
	}

	return nil
}
