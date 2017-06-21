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
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path"
	// "time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
	"golang.org/x/crypto/pbkdf2"
)

// A KeyType represent the type(s) of keys held by a Keys struct.
type KeyType int

// These are the types of supported keys.
const (
	Signing KeyType = 1 << iota
	Crypting
	Deriving
)

// -------------------------------------------------------------------

// Temporary

type Tao interface {
	// GetTaoName returns the Tao principal name assigned to the caller.
	GetTaoName() (name auth.Prin, err error)

	// ExtendTaoName irreversibly extends the Tao principal name of the caller.
	ExtendTaoName(subprin auth.SubPrin) error

	// GetRandomBytes returns a slice of n random bytes.
	GetRandomBytes(n int) (bytes []byte, err error)

	// Rand produces an io.Reader for random bytes from this Tao.
	Rand() io.Reader

	// GetSharedSecret returns a slice of n secret bytes.
	GetSharedSecret(n int, policy string) (bytes []byte, err error)

	// Attest requests the Tao host sign a statement on behalf of the caller. The
	// optional issuer, time and expiration will be given default values if nil.
	// TODO(kwalsh) Maybe create a struct for these optional params? Or use
	// auth.Says instead (in which time and expiration are optional) with a

	Attest(issuer *auth.Prin, time, expiration *int64, message auth.Form) (*Attestation, error)

	// Seal encrypts data so only certain hosted programs can unseal it.
	Seal(data []byte, policy string) (sealed []byte, err error)

	// Unseal decrypts data that has been sealed by the Seal() operation, but only
	// if the policy specified during the Seal() operation is satisfied.
	Unseal(sealed []byte) (data []byte, policy string, err error)

	// InitCounter initializes a counter with given label.
	InitCounter(label string, c int64) error

	// GetCounter retrieves a counter with given label.
	GetCounter(label string) (int64, error)

	// RollbackProtectedSeal encrypts data under rollback protection
	// so only certain hosted programs can unseal it.
	RollbackProtectedSeal(label string, data []byte, policy string) ([]byte, error)

	// RollbackProtectedUnseal decrypts data under rollback protection.
	RollbackProtectedUnseal(sealed []byte) ([]byte, string, error)
}

// -------------------------------------------------------------------

// Generate or restore a signer.
// InitializeSigner uses marshaledCryptoKey to restore a signer from
// a serialized CryptoKey if it's not nil; otherwise it generates one.
// If generated, the remainder of the arguments are used as parameters;
// otherwise they are ignored.
func InitializeSigner(marshaledCryptoKey []byte, keyType string, keyName *string, keyEpoch *int32, keyPurpose *string, keyStatus *string) (*Signer, error) {
	if marshaledCryptoKey != nil {
		k, err := UnmarshalCryptoKey(marshaledCryptoKey)
		if err != nil {
			return nil, errors.New("Can't UnmarshalCryptoKey")
		}
		s := SignerFromCryptoKey(*k)
		if s == nil {
			k.Clear()
			return nil, errors.New("Can't SignerFromCryptoKey")
		}
		if s.header.KeyPurpose == nil || *s.header.KeyPurpose != "signing" {
			k.Clear()
			s.Clear()
			return nil, errors.New("Recovered key not a signer")
		}
	}
	k := GenerateCryptoKey(keyType, keyName, keyEpoch, keyPurpose, keyStatus)
	if k == nil {
		return nil, errors.New("Can't GenerateCryptoKey")
	}
	s := SignerFromCryptoKey(*k)
	if s == nil {
		k.Clear()
		return nil, errors.New("Can't SignerFromCryptoKey")
	}
	if s.header.KeyPurpose == nil || *s.header.KeyPurpose != "signing" {
		k.Clear()
		s.Clear()
		return nil, errors.New("Recovered key not a signer")
	}
	return s, nil
}

// Generate or restore a crypter.
// InitializeCrypter uses marshaledCryptoKey to restore a signer from
// a serialized CryptoKey if it's not nil; otherwise it generates one.
// If generated, the remainder of the arguments are used as parameters;
// otherwise they are ignored.
func InitializeCrypter(marshaledCryptoKey []byte, keyType string, keyName *string, keyEpoch *int32, keyPurpose *string, keyStatus *string) (*Crypter, error) {
	if marshaledCryptoKey != nil {
		k, err := UnmarshalCryptoKey(marshaledCryptoKey)
		if err != nil {
			return nil, errors.New("Can't UnmarshalCryptoKey")
		}
		c := CrypterFromCryptoKey(*k)
		if c == nil {
			k.Clear()
			return nil, errors.New("Can't CrypterFromCryptoKey")
		}
		if c.header.KeyPurpose == nil || *c.header.KeyPurpose != "crypting" {
			k.Clear()
			c.Clear()
			return nil, errors.New("Recovered key not a crypter")
		}
	}
	k := GenerateCryptoKey(keyType, keyName, keyEpoch, keyPurpose, keyStatus)
	if k == nil {
		return nil, errors.New("Can't GenerateCryptoKey")
	}
	c := CrypterFromCryptoKey(*k)
	if c == nil {
		k.Clear()
		return nil, errors.New("Can't CrypterFromCryptoKey")
	}
	if c.header.KeyPurpose == nil || *c.header.KeyPurpose != "crypting" {
		k.Clear()
		c.Clear()
		return nil, errors.New("Recovered key not a crypter")
	}
	return c, nil
}

// Generate or restore a deriver.
// InitializeDeriver uses marshaledCryptoKey to restore a signer from
// a serialized CryptoKey if it's not nil; otherwise it generates one.
// If generated, the remainder of the arguments are used as parameters;
// otherwise they are ignored.
func InitializeDeriver(marshaledCryptoKey []byte, keyType string, keyName *string, keyEpoch *int32, keyPurpose *string, keyStatus *string) (*Deriver, error) {
	if marshaledCryptoKey != nil {
		k, err := UnmarshalCryptoKey(marshaledCryptoKey)
		if err != nil {
			return nil, errors.New("Can't UnmarshalCryptoKey")
		}
		d := DeriverFromCryptoKey(*k)
		if d == nil {
			k.Clear()
			return nil, errors.New("Can't DeriverFromCryptoKey")
		}
		if d.header.KeyPurpose == nil || *d.header.KeyPurpose != "deriving" {
			k.Clear()
			return nil, errors.New("Recovered key not a deriver")
		}
	}
	k := GenerateCryptoKey(keyType, keyName, keyEpoch, keyPurpose, keyStatus)
	if k == nil {
		return nil, errors.New("Can't GenerateCryptoKey")
	}
	d := DeriverFromCryptoKey(*k)
	if d == nil {
		k.Clear()
		return nil, errors.New("Can't DeriverFromCryptoKey")
	}
	if d.header.KeyPurpose == nil || *d.header.KeyPurpose != "deriving" {
		k.Clear()
		d.Clear()
		return nil, errors.New("Recovered key not a deriver")
	}
	return d, nil
}

// A Keys manages a set of signing, verifying, encrypting, and key-deriving
// keys.
type Keys struct {
	dir    string
	policy string

	// Key types in this structure
	keyTypes KeyType

	SigningKey   *Signer
	CryptingKey  *Crypter
	VerifyingKey *Verifier
	DerivingKey  *Deriver
	Delegation   *Attestation
	Cert         *x509.Certificate
}

// Encodes Keys into protobuf
func MarshalKeyset(k *Keys) (*CryptoKeyset, error) {
	// fill in keys, cert, attestation
	var cks [][]byte
	if k.keyTypes&Signing == Signing {
		ck := &CryptoKey{
			KeyHeader: k.SigningKey.header,
		}
		keyComponents, err := KeyComponentsFromSigner(k.SigningKey)
		if err != nil {
			return nil, errors.New("Can't get key components from signing key")
		}
		ck.KeyComponents = keyComponents
		serializedCryptoKey, err := proto.Marshal(ck)
		if err != nil {
			return nil, errors.New("Can't serialize signing key")
		}
		cks = append(cks, serializedCryptoKey)
	}

	if k.keyTypes&Crypting == Crypting {
		ck := &CryptoKey{
			KeyHeader: k.CryptingKey.header,
		}
		keyComponents, err := KeyComponentsFromCrypter(k.CryptingKey)
		if err != nil {
			return nil, errors.New("Can't get key components from crypting key")
		}
		ck.KeyComponents = keyComponents
		serializedCryptoKey, err := proto.Marshal(ck)
		if err != nil {
			return nil, errors.New("Can't serialize crypting key")
		}
		cks = append(cks, serializedCryptoKey)
	}

	if k.keyTypes&Deriving == Deriving {
		ck := &CryptoKey{
			KeyHeader: k.DerivingKey.header,
		}
		keyComponents, err := KeyComponentsFromDeriver(k.DerivingKey)
		if err != nil {
			return nil, errors.New("Can't get key components from deriving key")
		}
		ck.KeyComponents = keyComponents
		serializedCryptoKey, err := proto.Marshal(ck)
		if err != nil {
			return nil, errors.New("Can't serialize deriving key")
		}
		cks = append(cks, serializedCryptoKey)
	}

	ckset := &CryptoKeyset{
		Keys: cks,
	}
	if k.Cert != nil {
		ckset.Cert = k.Cert.Raw
	}
	return ckset, nil
}

// UnmarshalKeyset decodes a CryptoKeyset into a temporary Keys structure. Note
// that this Keys structure doesn't have any of its variables set.
func UnmarshalKeyset(cks *CryptoKeyset) (*Keys, error) {
	k := new(Keys)

	for i := 0; i < len(cks.Keys); i++ {
		var ck CryptoKey
		err := proto.Unmarshal(cks.Keys[i], &ck)
		if err != nil {
			return nil, errors.New("Can't unmarshal cryptokey")
		}
		if ck.KeyHeader.KeyType == nil {
			return nil, errors.New("Missing KeyType in CryptoHeader")
		}
		switch *ck.KeyHeader.KeyType {
		default:
		case "signing":
			k.Cert, err = x509.ParseCertificate(cks.Cert)
			if err != nil {
				return nil, errors.New("Can't parse certificate")
			}
			k.SigningKey = SignerFromCryptoKey(ck)
			if k.SigningKey == nil {
				return nil, errors.New("Can't recover signing key from cryptokey")
			}
			k.keyTypes |= Signing
		case "crypting":
			k.CryptingKey = CrypterFromCryptoKey(ck)
			if k.CryptingKey == nil {
				return nil, errors.New("Can't recover crypting key from cryptokey")
			}
			k.keyTypes |= Crypting
		case "deriving":
			k.DerivingKey = DeriverFromCryptoKey(ck)
			if k.DerivingKey == nil {
				return nil, errors.New("Can't recover deriving key from cryptokey")
			}
			k.keyTypes |= Deriving
		}
	}

	return k, nil
}

// The paths to the filename used by the Keys type.
const (
	X509Path            = "cert"
	PBEKeysetPath       = "keys"
	PBESignerPath       = "signer"
	SealedKeysetPath    = "sealed_keyset"
	PlaintextKeysetPath = "plaintext_keyset"
)

// X509Path returns the path to the verifier key, stored as an X.509
// certificate.
func (k *Keys) X509Path() string {
	if k.dir == "" {
		return ""
	}

	return path.Join(k.dir, X509Path)
}

// PBEKeysetPath returns the path for stored keys.
func (k *Keys) PBEKeysetPath() string {
	if k.dir == "" {
		return ""
	}
	return path.Join(k.dir, PBEKeysetPath)
}

// PBESignerPath returns the path for a stored signing key.
func (k *Keys) PBESignerPath() string {
	if k.dir == "" {
		return ""
	}
	return path.Join(k.dir, PBESignerPath)
}

// SealedKeysetPath returns the path for a stored signing key.
func (k *Keys) SealedKeysetPath() string {
	if k.dir == "" {
		return ""
	}

	return path.Join(k.dir, SealedKeysetPath)
}

// PlaintextKeysetPath returns the path for a key stored in plaintext (this is
// not normally the case).
func (k *Keys) PlaintextKeysetPath() string {
	if k.dir == "" {
		return ""
	}

	return path.Join(k.dir, PlaintextKeysetPath)
}

// NewTemporaryKeys creates a new Keys structure with the specified keys.
func NewTemporaryKeys(keyTypes KeyType) (*Keys, error) {
	k := &Keys{
		keyTypes: keyTypes,
	}
	if k.keyTypes == 0 || (k.keyTypes & ^Signing & ^Crypting & ^Deriving != 0) {
		return nil, errors.New("bad key type")
	}

	var err error
	if k.keyTypes&Signing == Signing {
		keyName := "Temporary_Keys_signer"
		keyType := SignerTypeFromSuiteName(TaoCryptoSuite)
		keyPurpose := "signing"
		keyStatus := "active"
		keyEpoch := int32(1)
		k.SigningKey, err = InitializeSigner(nil, *keyType, &keyName, &keyEpoch, &keyPurpose, &keyStatus)
		if err != nil {
			return nil, err
		}

		k.VerifyingKey = k.SigningKey.GetVerifierFromSigner()
	}

	if k.keyTypes&Crypting == Crypting {
		keyName := "Temporary_Keys_crypter"
		keyType := CrypterTypeFromSuiteName(TaoCryptoSuite)
		keyPurpose := "crypting"
		keyStatus := "active"
		keyEpoch := int32(1)
		k.CryptingKey, err = InitializeCrypter(nil, *keyType, &keyName, &keyEpoch, &keyPurpose, &keyStatus)
		if err != nil {
			return nil, err
		}
	}

	if k.keyTypes&Deriving == Deriving {
		keyName := "Temporary_Keys_deriver"
		keyType := DeriverTypeFromSuiteName(TaoCryptoSuite)
		keyPurpose := "deriving"
		keyStatus := "active"
		keyEpoch := int32(1)
		k.DerivingKey, err = InitializeDeriver(nil, *keyType, &keyName, &keyEpoch, &keyPurpose, &keyStatus)
		if err != nil {
			return nil, err
		}
	}
	return k, nil
}

// NewSignedOnDiskPBEKeys creates the same type of keys as NewOnDiskPBEKeys but
// signs a certificate for the signer with the provided Keys, which must have
// both a SigningKey and a Certificate.
func NewSignedOnDiskPBEKeys(keyTypes KeyType, password []byte, path string, name *pkix.Name, serial int, signer *Keys) (*Keys, error) {
	if signer == nil || name == nil {
		return nil, errors.New("must supply a signer and a name")
	}

	if signer.Cert == nil || signer.SigningKey == nil {
		return nil, newError("the signing key must have a SigningKey and a Cert")
	}

	if keyTypes&Signing == 0 {
		return nil, errors.New("can't sign a key that has no signer")
	}

	k, err := NewOnDiskPBEKeys(keyTypes, password, path, nil)
	if err != nil {
		return nil, err
	}

	// If there's already a cert, then this means that there was already a
	// keyset on disk, so don't create a new signed certificate.
	if k.Cert == nil {
		pkInt := PublicKeyAlgFromSignerAlg(*signer.SigningKey.header.KeyType)
		sigInt := SignatureAlgFromSignerAlg(*signer.SigningKey.header.KeyType)
		k.Cert, err = signer.SigningKey.CreateSignedX509(signer.Cert, serial, k.VerifyingKey, pkInt, sigInt, name)
		if err != nil {
			return nil, err
		}

		if err = util.WritePath(k.X509Path(), k.Cert.Raw, 0777, 0666); err != nil {
			return nil, err
		}
	}

	return k, nil
}

// NewOnDiskPBEKeys creates a new Keys structure with the specified key types
// store under PBE on disk. If keys are generated and name is not nil, then a
// self-signed x509 certificate will be generated and saved as well.
func NewOnDiskPBEKeys(keyTypes KeyType, password []byte, path string, name *pkix.Name) (*Keys, error) {
	if keyTypes == 0 || (keyTypes & ^Signing & ^Crypting & ^Deriving != 0) {
		return nil, newError("bad key type")
	}

	if path == "" {
		return nil, newError("bad init call: no path for keys")
	}

	k := &Keys{
		keyTypes: keyTypes,
		dir:      path,
	}

	if len(password) == 0 {
		// This means there's no secret information: just load a public
		// verifying key.
		if k.keyTypes & ^Signing != 0 {
			return nil, newError("without a password, only a verifying key can be loaded")
		}

		err := k.loadCert()
		if err != nil {
			return nil, err
		}
		if k.Cert == nil {
			return nil, newError("no password and can't load cert: %s", k.X509Path())
		}

		if k.VerifyingKey, err = FromX509(k.Cert); err != nil {
			return nil, err
		}
	} else {
		// Check to see if there are already keys.
		f, err := os.Open(k.PBEKeysetPath())
		if err == nil {
			defer f.Close()
			ks, err := ioutil.ReadAll(f)
			if err != nil {
				return nil, err
			}

			data, err := PBEDecrypt(ks, password)
			if err != nil {
				return nil, err
			}
			defer ZeroBytes(data)

			var cks CryptoKeyset
			if err = proto.Unmarshal(data, &cks); err != nil {
				return nil, err
			}

			// TODO(tmroeder): defer zeroKeyset(&cks)

			ktemp, err := UnmarshalKeyset(&cks)
			if err != nil {
				return nil, err
			}

			// Note that this loads the certificate if it's
			// present, and it returns nil otherwise.
			err = k.loadCert()
			if err != nil {
				return nil, err
			}

			k.SigningKey = ktemp.SigningKey
			k.VerifyingKey = ktemp.VerifyingKey
			k.CryptingKey = ktemp.CryptingKey
			k.DerivingKey = ktemp.DerivingKey
		} else {
			// Create and store a new set of keys.
			k, err = NewTemporaryKeys(keyTypes)
			if err != nil {
				return nil, err
			}

			k.dir = path

			cks, err := MarshalKeyset(k)
			if err != nil {
				return nil, err
			}

			// TODO(tmroeder): defer zeroKeyset(cks)

			m, err := proto.Marshal(cks)
			if err != nil {
				return nil, err
			}
			defer ZeroBytes(m)
			enc, err := PBEEncrypt(m, password)
			if err != nil {
				return nil, err
			}

			if err = util.WritePath(k.PBEKeysetPath(), enc, 0777, 0600); err != nil {
				return nil, err
			}

			if k.SigningKey != nil && name != nil {
				err = k.newCert(name)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	return k, nil
}

func (k *Keys) newCert(name *pkix.Name) (err error) {
	pkInt := PublicKeyAlgFromSignerAlg(*k.SigningKey.header.KeyType)
	sigInt := SignatureAlgFromSignerAlg(*k.SigningKey.header.KeyType)
	if pkInt < 0 || sigInt < 0 {
		return errors.New("No signing algorithm")
	}
	k.Cert, err = k.SigningKey.CreateSelfSignedX509(pkInt, sigInt, int64(1), name)
	if err != nil {
		return err
	}
	if err = util.WritePath(k.X509Path(), k.Cert.Raw, 0777, 0666); err != nil {
		return err
	}
	return nil
}

func (k *Keys) loadCert() error {
	f, err := os.Open(k.X509Path())
	// Allow this operation to fail silently, since there isn't always a
	// certificate available.
	if err != nil {
		return nil
	}
	defer f.Close()

	der, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	k.Cert, err = x509.ParseCertificate(der)
	return err
}

// NewTemporaryTaoDelegatedKeys initializes a set of temporary keys under a host
// Tao, using the Tao to generate a delegation for the signing key. Since these
// keys are never stored on disk, they are not sealed to the Tao.
func NewTemporaryTaoDelegatedKeys(keyTypes KeyType, t Tao) (*Keys, error) {
	k, err := NewTemporaryKeys(keyTypes)
	if err != nil {
		return nil, err
	}

	if t != nil && k.SigningKey != nil {

		self, err := t.GetTaoName()
		if err != nil {
			return nil, err
		}

		s := &auth.Speaksfor{
			Delegate:  k.SigningKey.ToPrincipal(),
			Delegator: self,
		}
		if k.Delegation, err = t.Attest(&self, nil, nil, s); err != nil {
			return nil, err
		}
	}

	return k, nil
}

// PBEEncrypt encrypts plaintext using a password to generate a key. Note that
// since this is for private program data, we don't try for compatibility with
// the C++ Tao version of the code.
func PBEEncrypt(plaintext, password []byte) ([]byte, error) {
	if password == nil || len(password) == 0 {
		return nil, newError("null or empty password")
	}
	// FIX: Should follow cryptosuite
	pbed := &PBEData{
		Version: CryptoVersion_CRYPTO_VERSION_2.Enum(),
		Cipher:  proto.String("aes128-ctr"),
		Hmac:    proto.String("sha256"),
		// The IV is required, so we include it, but this algorithm doesn't use it.
		Iv:         make([]byte, aes.BlockSize),
		Iterations: proto.Int32(4096),
		Salt:       make([]byte, aes.BlockSize),
	}

	// We use the first half of the salt for the AES key and the second
	// half for the HMAC key, since the standard recommends at least 8
	// bytes of salt.
	if _, err := rand.Read(pbed.Salt); err != nil {
		return nil, err
	}

	// 128-bit AES key.
	aesKey := pbkdf2.Key(password, pbed.Salt[:8], int(*pbed.Iterations), 16, sha256.New)
	defer ZeroBytes(aesKey)

	// 64-byte HMAC-SHA256 key.
	hmacKey := pbkdf2.Key(password, pbed.Salt[8:], int(*pbed.Iterations), 64, sha256.New)
	defer ZeroBytes(hmacKey)

	ver := CryptoVersion_CRYPTO_VERSION_2
	keyName := "PBEKey"
	keyEpoch := int32(1)
	// FIX: Should be derived from cryptosuite
	keyType := "aes128-ctr-hmacsha256"
	keyPurpose := "crypting"
	keyStatus := "active"
	ch := &CryptoHeader{
		Version:    &ver,
		KeyName:    &keyName,
		KeyEpoch:   &keyEpoch,
		KeyType:    &keyType,
		KeyPurpose: &keyPurpose,
		KeyStatus:  &keyStatus,
	}
	ck := &CryptoKey{
		KeyHeader: ch,
	}
	ck.KeyComponents = append(ck.KeyComponents, aesKey)
	ck.KeyComponents = append(ck.KeyComponents, hmacKey)
	c := CrypterFromCryptoKey(*ck)
	if c == nil {
		return nil, errors.New("Empty crypter")
	}
	// Note that we're abusing the PBEData format here, since the IV and
	// the MAC are actually contained in the ciphertext from Encrypt().
	var err error
	if pbed.Ciphertext, err = c.Encrypt(plaintext); err != nil {
		return nil, err
	}
	return proto.Marshal(pbed)
}

// PBEDecrypt decrypts ciphertext using a password to generate a key. Note that
// since this is for private program data, we don't try for compatibility with
// the C++ Tao version of the code.
func PBEDecrypt(ciphertext, password []byte) ([]byte, error) {
	if password == nil || len(password) == 0 {
		return nil, newError("null or empty password")
	}

	var pbed PBEData
	if err := proto.Unmarshal(ciphertext, &pbed); err != nil {
		return nil, err
	}

	// Recover the keys from the password and the PBE header.
	if *pbed.Version != CryptoVersion_CRYPTO_VERSION_2 {
		return nil, newError("bad version")
	}

	if *pbed.Cipher != "aes128-ctr" {
		return nil, newError("bad cipher")
	}

	if *pbed.Hmac != "sha256" {
		return nil, newError("bad hmac")
	}

	// 128-bit AES key.
	aesKey := pbkdf2.Key(password, pbed.Salt[:8], int(*pbed.Iterations), 16, sha256.New)
	defer ZeroBytes(aesKey)

	// 64-byte HMAC-SHA256 key.
	hmacKey := pbkdf2.Key(password, pbed.Salt[8:], int(*pbed.Iterations), 64, sha256.New)

	ck := new(CryptoKey)
	ver := CryptoVersion_CRYPTO_VERSION_2
	keyName := "PBEKey"
	keyEpoch := int32(1)
	// FIX: Should be derived from cryptosuite
	keyType := "aes128-ctr-hmacsha256"
	keyPurpose := "crypting"
	keyStatus := "active"
	ch := &CryptoHeader{
		Version:    &ver,
		KeyName:    &keyName,
		KeyEpoch:   &keyEpoch,
		KeyType:    &keyType,
		KeyPurpose: &keyPurpose,
		KeyStatus:  &keyStatus,
	}
	ck.KeyHeader = ch
	ck.KeyComponents = append(ck.KeyComponents, aesKey)
	ck.KeyComponents = append(ck.KeyComponents, hmacKey)
	c := CrypterFromCryptoKey(*ck)

	defer ZeroBytes(hmacKey)

	// Note that we're abusing the PBEData format here, since the IV and
	// the MAC are actually contained in the ciphertext from Encrypt().
	data, err := c.Decrypt(pbed.Ciphertext)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// NewOnDiskTaoSealedKeys sets up the keys sealed under a host Tao or reads sealed keys.
func NewOnDiskTaoSealedKeys(keyTypes KeyType, t Tao, path, policy string) (*Keys, error) {

	// Fail if no parent Tao exists (otherwise t.Seal() would not be called).
	if t == nil {
		return nil, errors.New("parent tao is nil")
	}

	k := &Keys{
		keyTypes: keyTypes,
		dir:      path,
		policy:   policy,
	}

	// Check if keys exist: if not, generate and save a new set.
	f, err := os.Open(k.SealedKeysetPath())
	if err != nil {
		k, err = NewTemporaryTaoDelegatedKeys(keyTypes, t)
		if err != nil {
			return nil, err
		}
		k.dir = path
		k.policy = policy

		if err = k.Save(t); err != nil {
			return k, err
		}
		return k, nil
	}
	f.Close()

	// Otherwise, load from file.
	return LoadKeys(keyTypes, t, path, policy)
}

// Save serializes, seals, and writes a key set to disk. It calls t.Seal().
func (k *Keys) Save(t Tao) error {
	// Marshal key set.
	cks, err := MarshalKeyset(k)
	if err != nil {
		return err
	}
	cks.Delegation = k.Delegation

	// TODO(tmroeder): defer zeroKeyset(cks)

	m, err := proto.Marshal(cks)
	if err != nil {
		return err
	}
	defer ZeroBytes(m)

	data, err := t.Seal(m, k.policy)
	if err != nil {
		return err
	}

	if err = util.WritePath(k.SealedKeysetPath(), data, 0700, 0600); err != nil {
		return err
	}

	return nil
}

// LoadKeys reads a key set from file. If there is a parent tao (t!=nil), then
// expect the keys are sealed and call t.Unseal(); otherwise, expect the key
// set to be plaintext.
func LoadKeys(keyTypes KeyType, t Tao, path, policy string) (*Keys, error) {
	k := &Keys{
		keyTypes: keyTypes,
		dir:      path,
		policy:   policy,
	}

	// Check to see if there are already keys.
	var keysetPath string
	if t == nil {
		keysetPath = k.PlaintextKeysetPath()
	} else {
		keysetPath = k.SealedKeysetPath()
	}
	f, err := os.Open(keysetPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ks, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var cks CryptoKeyset
	if t != nil {
		data, p, err := t.Unseal(ks)
		if err != nil {
			return nil, err
		}
		defer ZeroBytes(data)

		if p != policy {
			return nil, errors.New("invalid policy from Unseal")
		}
		if err = proto.Unmarshal(data, &cks); err != nil {
			return nil, err
		}

	} else {
		if err = proto.Unmarshal(ks, &cks); err != nil {
			return nil, err
		}
	}

	// TODO(tmroeder): defer zeroKeyset(&cks)

	ktemp, err := UnmarshalKeyset(&cks)
	if err != nil {
		return nil, err
	}

	k.SigningKey = ktemp.SigningKey
	k.VerifyingKey = ktemp.VerifyingKey
	k.CryptingKey = ktemp.CryptingKey
	k.DerivingKey = ktemp.DerivingKey

	// Read the delegation.
	k.Delegation = cks.Delegation

	return k, nil
}

// NewSecret creates and encrypts a new secret value of the given length, or it
// reads and decrypts the value and checks that it's the right length. It
// creates the file and its parent directories if these directories do not
// exist.
func (k *Keys) NewSecret(file string, length int) ([]byte, error) {
	if _, err := os.Stat(file); err != nil {
		// Create the parent directories and the file.
		if err := os.MkdirAll(path.Dir(file), 0700); err != nil {
			return nil, err
		}

		secret := make([]byte, length)
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}

		enc, err := k.CryptingKey.Encrypt(secret)
		if err != nil {
			return nil, err
		}

		if err := ioutil.WriteFile(file, enc, 0700); err != nil {
			return nil, err
		}

		return secret, nil
	}

	enc, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	dec, err := k.CryptingKey.Decrypt(enc)
	if err != nil {
		return nil, err
	}

	if len(dec) != length {
		ZeroBytes(dec)
		return nil, newError("The decrypted value had length %d, but it should have had length %d", len(dec), length)
	}

	return dec, nil
}

// SaveKeyset serializes and saves a Keys object to disk in plaintext.
func SaveKeyset(k *Keys, dir string) error {
	k.dir = dir
	cks, err := MarshalKeyset(k)
	if err != nil {
		return err
	}
	cks.Delegation = k.Delegation

	m, err := proto.Marshal(cks)
	if err != nil {
		return err
	}

	if err = util.WritePath(k.PlaintextKeysetPath(), m, 0700, 0600); err != nil {
		return err
	}

	return nil
}
