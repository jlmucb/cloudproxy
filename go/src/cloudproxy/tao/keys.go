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
	"crypto/x509"
	"errors"
	"io/ioutil"
	"os"
	"path"
	"strconv"

	"code.google.com/p/goprotobuf/proto"
	key "github.com/dgryski/dkeyczar"
)

var _ = key.NewKeyManager

type KeyType int

const (
	Signing     KeyType = 1 << iota
	Crypting    KeyType = 1 << iota
	KeyDeriving KeyType = 1 << iota
	X509	    KeyType = 1 << iota
)

type Keys struct {
	nickname string
	dir string
	policy string

	signer key.Signer
	crypter key.Crypter
	verifer key.Verifier
	keyDeriver key.Signer
	delegation *Attestation
	cert *x509.Certificate
}

func writeKeys(km key.KeyManager, enc key.Encrypter, kp string) error {
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

func (k *Keys) instantiateKey(keyType KeyType, keyPath, name string, crypter key.Crypter) error {
	var r key.KeyReader
	var err error
	if _, err = os.Stat(keyPath); !os.IsNotExist(err) {
		if crypter != nil {
			fr := key.NewFileReader(keyPath)
			r = key.NewEncryptedReader(fr, crypter)
		} else {
			r = key.NewFileReader(keyPath)
		}
	} else {
		km := key.NewKeyManager()
		var size uint
		if keyType == Signing {
			err = km.Create(name, key.P_SIGN_AND_VERIFY, key.T_RSA_PRIV)
			size = 2048
		} else if keyType == Crypting {
			err = km.Create(name, key.P_DECRYPT_AND_ENCRYPT, key.T_AES)
			size = 256
		} else if keyType == KeyDeriving {
			err = km.Create(name, key.P_SIGN_AND_VERIFY, key.T_HMAC_SHA1)
			size = 256
		} else {
			return errors.New("Invalid Tao Keys type")
		}

		if err != nil {
			return err
		}

		if err = km.AddKey(size, key.S_PRIMARY); err != nil {
			return err
		}

		r = key.NewJSONKeyReader(km.ToJSONs(nil))
		if keyPath != "" {
			if err = writeKeys(km, crypter, keyPath); err != nil {
				return err
			}
		}
	}

	if keyType == Signing {
		k.signer, err = key.NewSigner(r)
	} else if keyType == Crypting {
		k.crypter, err = key.NewCrypter(r)
	} else if keyType == KeyDeriving {
		k.keyDeriver, err = key.NewSigner(r)
	} else {
		err = errors.New("Invalid Tao Key type")
	}

	return err
}

func (k *Keys) SignerPath() string {
	if k.dir == "" {
		return ""
	} else {
		return path.Join(k.dir, "signer")
	}
}

func (k *Keys) SignerName() string {
	return k.nickname + "_signer"
}

func (k *Keys) CrypterPath() string {
	if k.dir == "" {
		return ""
	} else {
		return path.Join(k.dir, "crypter")
	}
}

func (k *Keys) CrypterName() string {
	return k.nickname + "_crypter"
}

func (k *Keys) KeyDeriverPath() string {
	if k.dir == "" {
		return ""
	} else {
		return path.Join(k.dir, "key_deriver")
	}
}

func (k *Keys) KeyDeriverName() string {
	return k.nickname + "_key_deriver"
}

func (k *Keys) TaoSecretPath() string {
	if k.dir == "" {
		return ""
	} else {
		return path.Join(k.dir, "secret")
	}
}

func (k *Keys) instantiate(keyTypes KeyType, crypter key.Crypter) error {
	if keyTypes & Signing == Signing {
		if err := k.instantiateKey(Signing, k.SignerPath(), k.SignerName(), crypter); err != nil {
			return err
		}
	}

	if keyTypes & Crypting == Crypting {
		if err := k.instantiateKey(Crypting, k.CrypterPath(), k.CrypterName(), crypter); err != nil {
			return err
		}
	}

	if keyTypes & KeyDeriving == KeyDeriving {
		if err := k.instantiateKey(KeyDeriving, k.KeyDeriverPath(), k.KeyDeriverName(), crypter); err != nil {
			return err
		}
	}

	return nil
}

func NewTempKeys(nickname string, keyTypes KeyType) *Keys {
	// For temp keys, there aren't any paths, so the keys aren't written to disk.
	k := &Keys{
		nickname: nickname,
	}

	if err := k.instantiate(keyTypes, nil); err != nil {
		return nil
	}

	return k
}

func NewTempHostedKeys(nickname string, keyTypes KeyType, tao Tao) *Keys {
	// For temp keys, there aren't any paths, so the keys aren't written to disk.
	k := &Keys{
		nickname: nickname,
	}

	var err error
	if err = k.instantiate(keyTypes, nil); err != nil {
		return nil
	}

	s := &Statement{
		Issuer: proto.String("soft_tao"),
	}

	if k.delegation, err = tao.Attest(s); err != nil {
		return nil
	}

	return k
}

func NewNonHostedKeys(dir, password, nickname string, keyTypes KeyType) *Keys {
	k := &Keys{
		nickname: nickname,
		dir: dir,
	}

	pbe := key.NewPBECrypter([]byte(password))
	var err error
	if err = k.instantiate(keyTypes, pbe); err != nil {
		return nil
	}

	return k
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

var secretLength int = 128

func (k *Keys) newTaoPBECrypter(tao Tao) (key.Crypter, error) {
	// Create or read the secret, using the Tao.
	secretPath := k.TaoSecretPath()
	var err error
	var sec []byte
	if _, err = os.Stat(secretPath); !os.IsNotExist(err) {
		sec = make([]byte, secretLength)
		if err = tao.GetRandomBytes(sec); err != nil {
			return nil, err
		}
		defer zeroBytes(sec)

		sealed, err := tao.Seal(sec, []byte(k.policy))
		if err != nil {
			return nil, err
		}

		if err = ioutil.WriteFile(secretPath, sealed, 0600); err != nil {
			return nil, err
		}


	} else {
		sealed, err := ioutil.ReadFile(secretPath)
		if err != nil {
			return nil, err
		}

		if sec, _, err = tao.Unseal(sealed); err != nil {
			return nil, err
		}
		defer zeroBytes(sec)
	}

	return key.NewPBECrypter(sec), nil
}

func NewHostedKeys(dir, policy, nickname string, keyTypes KeyType, tao Tao) *Keys {
	k := &Keys{
		nickname: nickname,
		dir: dir,
	}

	pbe, err := k.newTaoPBECrypter(tao)
	if err != nil {
		return nil
	}

	if err = k.instantiate(keyTypes, pbe); err != nil {
		return nil
	}

	s := &Statement{
		Issuer: proto.String("soft_tao"),
	}

	if k.delegation, err = tao.Attest(s); err != nil {
		return nil
	}

	return k
}

func (k *Keys) Sign(msg, context []byte) (string, error) {
	if k.signer == nil {
		return "", errors.New("No signer available")
	}

	sd := &SignedData{
		Context: proto.String(string(context)),
		Data: msg,
	}

	s, err := proto.Marshal(sd)
	if err != nil {
		return "", err
	}

	return k.signer.Sign(s)
}

func (k *Keys) Verify(msg, context, signature []byte) (bool, error) {
	if k.signer == nil {
		return false, errors.New("No signer available")
	}

	sd := &SignedData{
		Context: proto.String(string(context)),
		Data: msg,
	}

	s, err := proto.Marshal(sd)
	if err != nil {
		return false, err
	}

	return k.signer.Verify(s, string(signature))
}
