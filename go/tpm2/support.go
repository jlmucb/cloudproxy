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

// Package tpm2 supports direct communication with a tpm 2.0 device under Linux.

package tpm2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	// "encoding/hex"
	"errors"
	"fmt"
	// "io"
	"math/big"
	// "net"
	"os"
	// "time"

	// "github.com/golang/protobuf/proto"
)


//
//  Crypto helper functions
//

func PublicKeyFromPrivate(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	default:
	return nil
	}
}

func KDFA(alg uint16, key []byte, label string, contextU []byte, contextV []byte, bits int) ([]byte, error) {
	counter := uint32(0)
	bytes_left := (bits + 7) / 8;
	var out []byte
	for ; bytes_left > 0 ; {
		counter = counter + 1
		if alg == AlgTPM_ALG_SHA1 {
			mac := hmac.New(sha1.New, key)
			// copy counter (big Endian), label, contextU, contextV, bits (big Endian)
			outa,_ := pack([]interface{}{&counter})
			var arr [32]byte
			copy(arr[0:], label)
			arr[len(label)] = 0
			outc := append(contextU, contextV...)
			u_bits := uint32(bits)
			outd,_ := pack([]interface{}{&u_bits})
			in := append(outa, append(arr[0:len(label)+1], append(outc, outd...)...)...)
			mac.Write(in)
			out = append(out, mac.Sum(nil)...)
			bytes_left -= 20
		} else if alg == AlgTPM_ALG_SHA256 {
			mac := hmac.New(sha256.New, key)
			// copy counter (big Endian), label, contextU, contextV, bits (big Endian)
			outa, _ := pack([]interface{}{&counter})
			var arr [32]byte
			copy(arr[0:], label)
			arr[len(label)] = 0
			outc := append(contextU, contextV...)
			u_bits := uint32(bits)
			outd,_ := pack([]interface{}{&u_bits})
			in := append(outa, append(arr[0:len(label)+1], append(outc, outd...)...)...)
			mac.Write(in)
			out = append(out, mac.Sum(nil)...)
			bytes_left -= 32
		} else {
			return nil, errors.New("Unsupported key hmac alg")
		}
	}
	return out, nil
}

//	Return: out_hmac, output_data
func EncryptDataWithCredential(encrypt_flag bool, hash_alg_id uint16,
		unmarshaled_credential []byte, inData []byte,
		inHmac []byte) ([]byte, []byte, error) {
	var contextV []byte
	derivedKeys, err := KDFA(hash_alg_id, unmarshaled_credential,
		"PROTECT", contextV, contextV, 512)
	if err != nil {
		fmt.Printf("EncryptDataWithCredential can't derive keys\n")
		return nil, nil, errors.New("KDFA failed")
	}
	var calculatedHmac []byte
	outData := make([]byte, len(inData), len(inData))
	iv := derivedKeys[16:32]
	key := derivedKeys[0:16]
	dec, err := aes.NewCipher(key)
	ctr := cipher.NewCTR(dec, iv)
	ctr.XORKeyStream(outData, inData)

	var toHash []byte
	if encrypt_flag == true {
		toHash =  inData
	} else {
		toHash = outData
	}
	// Calculate hmac on output data
	if hash_alg_id == AlgTPM_ALG_SHA1 {
		hm := hmac.New(sha1.New, derivedKeys[48:64])
		hm.Write(toHash)
		calculatedHmac = hm.Sum(nil)
	} else if hash_alg_id == AlgTPM_ALG_SHA256 {
		hm := hmac.New(sha256.New, derivedKeys[32:64])
		hm.Write(toHash)
		calculatedHmac = hm.Sum(nil)
	} else {
		fmt.Printf("EncryptDataWithCredential unrecognized hmac alg\n")
		return nil, nil, errors.New("Unsupported Hash alg")
	}

	if encrypt_flag == false {
		if bytes.Compare(calculatedHmac, inHmac) != 0 {
			return nil, nil, errors.New("Integrity check fails")
		}
	}

	return calculatedHmac, outData, nil
}

// Returns encrypted secret.
func encryptHack (hash_alg_id uint16, modSize int,
		  protectorPublic *rsa.PublicKey, seed []byte,
		  label []byte) ([]byte, error) {

	private, err := rsa.GenerateKey(rand.Reader, modSize)
	if  err != nil || private == nil {
		return nil, errors.New("Can't gen private key")
	}
	public := &private.PublicKey

	var fake_encrypted_secret []byte
	if hash_alg_id == uint16(AlgTPM_ALG_SHA1) {
		fake_encrypted_secret, err = rsa.EncryptOAEP(sha1.New(),
			rand.Reader, public, seed, label)
	} else if hash_alg_id == uint16(AlgTPM_ALG_SHA256) {
		fake_encrypted_secret, err = rsa.EncryptOAEP(sha256.New(),
			rand.Reader, public, seed, label)
	} else {
		return nil, errors.New("Unsupported hash")
	}
	if  err != nil {
		return nil, errors.New("Can't fake encrypt")
	}
	fmt.Printf("encrypted_secret: %x\n", fake_encrypted_secret)
	var N *big.Int
	var D *big.Int
	var x *big.Int
	var z *big.Int
	N = public.N
	D = private.D
	x = new(big.Int)
	z = new(big.Int)
	x.SetBytes(fake_encrypted_secret)
	z = z.Exp(x, D, N)
	decrypted_pad := z.Bytes()
	fmt.Printf("decrypted with pad (%d): %x\n", len(decrypted_pad), decrypted_pad)
	// zero := []byte{0}
	// decrypted_pad = append(zero, decrypted_pad...)
	// fmt.Printf("new pad (%d): %x\n", len(decrypted_pad), decrypted_pad)

	// Now encrypt with real key
	var M *big.Int
	var E *big.Int
	var u *big.Int
	var w *big.Int
	M = protectorPublic.N
	E = big.NewInt(int64(protectorPublic.E))
	u = new(big.Int)
	w = new(big.Int)
	u.SetBytes(decrypted_pad)
	w = w.Exp(u, E, M)
	encrypted_secret  := w.Bytes()
	return encrypted_secret, nil
}

// Retieve file.
func RetrieveFile(fileName string) ([]byte) {
	fileInfo, err := os.Stat(fileName)
	if err != nil {
		return nil
	}
	buf := make([]byte, fileInfo.Size())
	fileHandle, err := os.Open(fileName)
	if err != nil {
		return nil
	}
	read, err := fileHandle.Read(buf)
	if int64(read) < fileInfo.Size() || err != nil {
		fileHandle.Close()
	return nil
	}
	fileHandle.Close()
	return buf
}

func ComputeHashValue(alg uint16, to_hash []byte) ([]byte, error) {
	if alg ==  uint16(AlgTPM_ALG_SHA1) {
		hash := sha1.New()
		hash.Write(to_hash)
		hash_value := hash.Sum(nil)
		return hash_value, nil
	} else if alg == uint16(AlgTPM_ALG_SHA256) {
		hash:= sha256.New()
		hash.Write(to_hash)
		hash_value := hash.Sum(nil)
		return hash_value, nil
	} else {
		return nil, errors.New("unsupported hash alg")
	}
}

func SizeHash(alg_id uint16) (int) {
	if alg_id == uint16(AlgTPM_ALG_SHA1) {
		return 20
	} else if alg_id == uint16(AlgTPM_ALG_SHA256) {
		return 32
	} else {
		return -1
	}
}

func VerifyDerCert(der_cert []byte, der_signing_cert []byte) (bool, error) {
	roots := x509.NewCertPool()
	opts := x509.VerifyOptions{
		Roots:   roots,
	}

	// Verify key
	policy_cert, err := x509.ParseCertificate(der_signing_cert)
	if err != nil {
		fmt.Printf("Signing ParseCertificate fails")
		return false, err
	}
	roots.AddCert(policy_cert)
	fmt.Printf("Root cert: %x\n", der_signing_cert)

	// Verify key
	cert, err := x509.ParseCertificate(der_cert)
	if err != nil {
		fmt.Printf("Cert ParseCertificate fails")
		return false, err
	}
	fmt.Printf("Cert: %x\n", cert)

	roots.AddCert(policy_cert)
	opts.Roots = roots
	chains, err := cert.Verify(opts)
	if err != nil {
		fmt.Printf("Verify fails ", err, "\n")
		return false, err
	}
	if chains != nil {
		fmt.Printf("Verify\n")
		return true, nil
	} else {
		fmt.Printf("Verify no verify\n")
		return false, nil
	}

}

func MarshalRsaPrivateToProto(key *rsa.PrivateKey) (*RsaPrivateKeyMessage, error) {
	if key == nil {
		return nil, errors.New("No key")
	}
	msg := new(RsaPrivateKeyMessage)
	msg.PublicKey = new(RsaPublicKeyMessage)
	msg.D = key.D.Bytes()
	msg.PublicKey.Exponent = []byte{0,1,0,1}
	msg.PublicKey.Modulus = key.N.Bytes()
	l := int32(len(msg.PublicKey.Modulus) * 8)
	msg.PublicKey.BitModulusSize = &l
	// if len(key.Primes == 2 {
	// 	msg.PublicKey.P = msg.Primes[0].Bytes()
	// 	msg.PublicKey.Q = msg.Primes[1].Bytes()
	// }
	return msg, nil
}

func UnmarshalRsaPrivateFromProto(msg *RsaPrivateKeyMessage) (*rsa.PrivateKey, error) {
	if msg == nil {
		return nil, errors.New("No message")
	}
	key := new(rsa.PrivateKey)
	// key.PublicKey = new(rsa.PublicKey)
	key.D = new(big.Int)
	key.D.SetBytes(msg.D)
	key.PublicKey.N = new(big.Int)
	key.PublicKey.N.SetBytes(msg.PublicKey.Modulus)
	key.PublicKey.E = 0x10001  // Fix
	// if msg.PublicKey.P != nil && msg.PublicKey.Q != nil {
	// 	msg.Primes[0] = new(big.Int)
	// 	msg.Primes[1] = new(big.Int)
	// 	msg.Primes[0].SetBytes(msg.PublicKey.P)
	// 	msg.Primes[1].SetBytes(msg.PublicKey.Q)
	// }
	return key, nil
}

