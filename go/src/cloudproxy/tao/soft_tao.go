//  Copyright (c) 2014, Google Inc.  All rights reserved.
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

package tao

import (
	"crypto/rand"
	"errors"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"time"

	"code.google.com/p/goprotobuf/proto"
	key "github.com/dgryski/dkeyczar"
)

// A SoftTao is an implementation of the Tao that isn't backed by any hardware
// mechanisms.
type SoftTao struct {
	crypter    key.Crypter
	signer     key.Signer
	name       string
	delegation []byte
}

// WriteKeys creates the directory path and writes the keyczar structure into
// it. Pass a nil Encrypter to skip encryption for the key information on disk.
func WriteKeys(km key.KeyManager, enc key.Encrypter, kp string) error {
	d := km.ToJSONs(enc)

	var err error
	if err = os.MkdirAll(kp, 0700); err != nil {
		return err
	}

	for i, s := range d {
		// The first JSON string is the meta file, and the rest are
		// keys.
		if i == 0 {
			if err = ioutil.WriteFile(path.Join(kp, "meta"), []byte(s), 0600); err != nil {
				return err
			}
		} else {
			keyNum := strconv.FormatInt(int64(i), 10)
			if err = ioutil.WriteFile(path.Join(kp, keyNum), []byte(s), 0600); err != nil {
				return err
			}
		}
	}

	return nil
}

// Init initializes the SoftTao with a crypter and a signer.
func (s *SoftTao) Init(name, crypterPath, signerPath string) error {
	s.name = name

	var err error
	var cr key.KeyReader
	if _, err = os.Stat(crypterPath); os.IsNotExist(err) {
		km := key.NewKeyManager()
		if err = km.Create("softtao_crypt", key.P_DECRYPT_AND_ENCRYPT, key.T_AES); err != nil {
			return err
		}

		if err = km.AddKey(256, key.S_PRIMARY); err != nil {
			return err
		}

		cr = key.NewJSONKeyReader(km.ToJSONs(nil))
		if crypterPath != "" {
			if err = WriteKeys(km, nil, crypterPath); err != nil {
				return err
			}
		}
	} else {
		cr = key.NewFileReader(crypterPath)
	}

	if s.crypter, err = key.NewCrypter(cr); err != nil {
		return err
	}

	var sr key.KeyReader
	if _, err = os.Stat(signerPath); os.IsNotExist(err) {
		km := key.NewKeyManager()
		// TODO(tmroeder): add ECDSA support.
		if err = km.Create("softtao_sign", key.P_SIGN_AND_VERIFY, key.T_RSA_PRIV); err != nil {
			return err
		}

		if err = km.AddKey(2048, key.S_PRIMARY); err != nil {
			return err
		}

		sr = key.NewJSONKeyReader(km.ToJSONs(nil))
		if signerPath != "" {
			if err = WriteKeys(km, nil, signerPath); err != nil {
				return err
			}
		}
	} else {
		sr = key.NewFileReader(signerPath)
	}

	if s.signer, err = key.NewSigner(sr); err != nil {
		return err
	}

	return nil
}

// GetRandomBytes fills the slice with random bytes.
func (s *SoftTao) GetRandomBytes(bytes []byte) error {
	if _, err := rand.Read(bytes); err != nil {
		return err
	}

	return nil
}

// Seal encrypts the data in a way that can only be opened by the Tao for the
// program that sealed it.  In the case of the SoftTao, this policy is
// implicit.
func (s *SoftTao) Seal(data, policy []byte) ([]byte, error) {
	// The SoftTao insists on the trivial policy, since it just encrypts the bytes directly
	if string(policy) != SealPolicyDefault {
		return nil, errors.New("The SoftTao requires SealPolicyDefault")
	}

	c, err := s.crypter.Encrypt(data)
	return []byte(c), err
}

func (s *SoftTao) Unseal(sealed []byte) (data, policy []byte, err error) {
	data, err = s.crypter.Decrypt(string(sealed))
	policy = []byte(SealPolicyDefault)
	return data, policy, err
}

func (s *SoftTao) Attest(stmt *Statement) (*Attestation, error) {
	st := new(Statement)
	proto.Merge(st, stmt)

	if st.Issuer == nil {
		st.Issuer = proto.String(s.name)
	} else if st.GetIssuer() != s.name {
		return nil, errors.New("Invalid issuer in statement")
	}

	if st.Time == nil {
		st.Time = proto.Int64(time.Now().UnixNano())
	}

	if st.Expiration == nil {
		st.Expiration = proto.Int64(st.GetTime() + DefaultAttestTimeout)
	}

	ser, err := proto.Marshal(st)
	if err != nil {
		return nil, err
	}

	sig, err := s.signer.AttachedSign(ser, []byte(AttestationSigningContext))
	if err != nil {
		return nil, err
	}

	a := new(Attestation)
	a.SerializedStatement = ser
	a.Signature = []byte(sig)
	a.Signer = proto.String(s.name)
	if s.delegation != nil {
		a.SerializedDelegation = s.delegation
	}

	return a, nil
}
