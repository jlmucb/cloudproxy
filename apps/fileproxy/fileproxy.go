// Copyright (c) 2014, Google, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// File: fileproxy.go

package fileproxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"

	"code.google.com/p/goprotobuf/proto"

	"github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
	"github.com/jlmucb/cloudproxy/util"
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
	na, err := RequestKeyNegoAttestation(network, addr, k, v)
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

// RequestKeyNegoAttestation connects to a CA instance, sends the attestation
// for an X.509 certificate, and gets back a certificate with a new principal
// name based on the policy key. This certificate is rooted in the policy key.
func RequestKeyNegoAttestation(network, addr string, keys *tao.Keys, v *tao.Verifier) (*tao.Attestation, error) {
	if keys.Cert == nil {
		return nil, errors.New("client: can't dial with an empty client certificate\n")
	}
	tlsCert, err := taonet.EncodeTLSCert(keys)
	if err != nil {
		return nil, err
	}
	conn, err := tls.Dial(network, addr, &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*tlsCert},
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Tao handshake: send client delegation.
	ms := util.NewMessageStream(conn)
	if _, err = ms.WriteMessage(keys.Delegation); err != nil {
		return nil, err
	}

	// Read the truncated attestation and check it.
	var a tao.Attestation
	if err := ms.ReadMessage(&a); err != nil {
		return nil, err
	}

	ok, err := v.Verify(a.SerializedStatement, tao.AttestationSigningContext, a.Signature)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("invalid attestation signature from Tao CA")
	}

	return &a, nil
}

func ZeroBytes(buf []byte) {
	n := len(buf)
	for i := 0; i < n; i++ {
		buf[i] = 0
	}
}

func PrincipalNameFromDERCert(derCert []byte) (string, error) {
	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		return "", err
	}
	cn := cert.Subject.CommonName
	return cn, nil
}

// returns sealed symmetric key, sealed signing key, DER encoded cert, delegation, error
func LoadProgramKeys(dir string) ([]byte, []byte, []byte, []byte, error) {
	ssymk := path.Join(dir, "sealedsymmetrickey")
	ssignk := path.Join(dir, "sealedsigningkey")
	scert := path.Join(dir, "signerCert")
	sealsymk := path.Join(dir, "sealedsymmetricKey")
	dblob := path.Join(dir, "delegationBlob")
	_, err := os.Stat(ssymk)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	_, err = os.Stat(ssignk)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	_, err = os.Stat(scert)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	sealedSymmetricKey, err := ioutil.ReadFile(sealsymk)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	log.Printf("fileproxy: Got sealedSymmetricKey\n")
	sealedSigningKey, err := ioutil.ReadFile(ssignk)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	log.Printf("fileproxy: Got sealedSigningKey\n")
	derCert, err := ioutil.ReadFile(scert)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	log.Printf("fileproxy: Got signerCert\n")
	ds, err := ioutil.ReadFile(dblob)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	log.Printf("LoadProgramKeys succeeded\n")
	return sealedSymmetricKey, sealedSigningKey, derCert, ds, nil
}

func CreateSigningKey(t tao.Tao) (*tao.Keys, []byte, error) {
	log.Printf("CreateSigningKey\n")
	self, err := t.GetTaoName()
	k, err := tao.NewTemporaryKeys(tao.Signing)
	if k == nil || err != nil {
		return nil, nil, errors.New("Can't generate signing key")
	}
	publicString := strings.Replace(self.String(), "(", "", -1)
	publicString = strings.Replace(publicString, ")", "", -1)
	details := tao.X509Details{
		Country:      "US",
		Organization: "Google",
		CommonName:   publicString}
	subjectname := tao.NewX509Name(details)
	derCert, err := k.SigningKey.CreateSelfSignedDER(subjectname)
	if err != nil {
		return nil, nil, errors.New("Can't self sign cert\n")
	}
	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		return nil, nil, err
	}
	k.Cert = cert
	s := &auth.Speaksfor{
		Delegate:  k.SigningKey.ToPrincipal(),
		Delegator: self}
	if s == nil {
		return nil, nil, errors.New("Can't produce speaksfor")
	}
	if k.Delegation, err = t.Attest(&self, nil, nil, s); err != nil {
		return nil, nil, err
	}
	if err == nil {
		_, _ = auth.UnmarshalForm(k.Delegation.SerializedStatement)
	}
	return k, derCert, nil
}

func InitializeSealedSymmetricKeys(dir string, t tao.Tao, keysize int) ([]byte, error) {
	log.Printf("InitializeSealedSymmetricKeys\n")
	unsealed, err := tao.Parent().GetRandomBytes(keysize)
	if err != nil {
		return nil, errors.New("Can't get random bytes")
	}
	sealed, err := tao.Parent().Seal(unsealed, tao.SealPolicyDefault)
	if err != nil {
		return nil, errors.New("Can't seal random bytes")
	}
	ioutil.WriteFile(path.Join(dir, "sealedsymmetrickey"), sealed, os.ModePerm)
	return unsealed, nil
}

func InitializeSealedSigningKey(caAddr, dir string, t tao.Tao, domain tao.Domain) (*tao.Keys, error) {
	log.Printf("InitializeSealedSigningKey\n")
	k, derCert, err := CreateSigningKey(t)
	if err != nil {
		log.Printf("fileproxy: CreateSigningKey failed with error %s\n", err)
		return nil, err
	}
	if derCert == nil {
		log.Printf("fileproxy: CreateSigningKey failed, no dercert\n")
		return nil, errors.New("No DER cert")
	}
	na, err := RequestKeyNegoAttestation("tcp", caAddr, k, domain.Keys.VerifyingKey)
	if err != nil {
		log.Printf("fileproxy: error from taonet.RequestTruncatedAttestation\n")
		return nil, err
	}
	if na == nil {
		return nil, errors.New("tao returned nil attestation")
	}
	k.Delegation = na
	pa, _ := auth.UnmarshalForm(na.SerializedStatement)
	var saysStatement *auth.Says
	if ptr, ok := pa.(*auth.Says); ok {
		saysStatement = ptr
	} else if val, ok := pa.(auth.Says); ok {
		saysStatement = &val
	}
	sf, ok := saysStatement.Message.(auth.Speaksfor)
	if ok != true {
		return nil, errors.New("says doesnt have speaksfor message")
	}
	kprin, ok := sf.Delegate.(auth.Term)
	if ok != true {
		return nil, errors.New("speaksfor message doesnt have Delegate")
	}
	newCert := auth.Bytes(kprin.(auth.Bytes))
	k.Cert, err = x509.ParseCertificate(newCert)
	if err != nil {
		log.Printf("can't parse returned certificate", err)
		log.Printf("\n")
		return nil, err
	}
	signingKeyBlob, err := tao.MarshalSignerDER(k.SigningKey)
	if err != nil {
		return nil, errors.New("Can't produce signing key blob")
	}
	sealedSigningKey, err := t.Seal(signingKeyBlob, tao.SealPolicyDefault)
	if err != nil {
		return nil, errors.New("Can't seal signing key")
	}
	ssignk := path.Join(dir, "sealedsigningKey")
	scert := path.Join(dir, "signerCert")
	dblob := path.Join(dir, "delegationBlob")
	err = ioutil.WriteFile(ssignk, sealedSigningKey, os.ModePerm)
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(scert, newCert, os.ModePerm)
	if err != nil {
		return nil, err
	}
	delegateBlob, err := proto.Marshal(k.Delegation)
	if err != nil {
		return nil, errors.New("Can't seal random bytes")
	}
	err = ioutil.WriteFile(dblob, delegateBlob, os.ModePerm)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func SigningKeyFromBlob(t tao.Tao, sealedKeyBlob []byte, certBlob []byte, delegateBlob []byte) (*tao.Keys, error) {
	log.Printf("SigningKeyFromBlob\n")
	k := &tao.Keys{}
	cert, err := x509.ParseCertificate(certBlob)
	if err != nil {
		return nil, err
	}
	k.Cert = cert
	k.Delegation = new(tao.Attestation)
	err = proto.Unmarshal(delegateBlob, k.Delegation)
	if err != nil {
		return nil, err
	}
	log.Printf("SigningKeyFromBlob: unmarshaled\n")
	signingKeyBlob, policy, err := tao.Parent().Unseal(sealedKeyBlob)
	if err != nil {
		log.Printf("fileproxy: signingkey unsealing error: %s\n", err)
	}
	if policy != tao.SealPolicyDefault {
		log.Printf("fileproxy: unexpected policy on unseal\n")
	}
	log.Printf("fileproxy: Unsealed Signing Key blob: %x\n", signingKeyBlob)
	k.SigningKey, err = tao.UnmarshalSignerDER(signingKeyBlob)
	k.Cert = cert
	return k, err
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
			var readSize int64 = bufferSize
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
		var readSize int64 = bufferSize
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
