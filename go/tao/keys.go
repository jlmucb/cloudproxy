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
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"

	"golang.org/x/crypto/hkdf"
)

// ZeroBytes clears the bytes in a slice.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func randBytes(size int) ([]byte, error) {
	buf := make([]byte, size)
	_, err := rand.Read(buf)
	return buf, err
}

func SerializeRsaPrivateComponents(rsaKey *rsa.PrivateKey) ([][]byte, error) {
	// mod, e, d, p, q
	var keyComponents [][]byte
	if rsaKey.PublicKey.N == nil {
		return nil, errors.New("No modulus")
	}
	keyComponents = append(keyComponents, rsaKey.PublicKey.N.Bytes())
	e := rsaKey.PublicKey.E
	eInt := big.NewInt(int64(e))
	keyComponents = append(keyComponents, eInt.Bytes())
	d := rsaKey.D
	if d == nil {
		return keyComponents, nil
	}
	keyComponents = append(keyComponents, d.Bytes())
	p := rsaKey.Primes[0]
	if p == nil {
		return keyComponents, nil
	}
	keyComponents = append(keyComponents, p.Bytes())
	q := rsaKey.Primes[1]
	if q == nil {
		return keyComponents, nil
	}
	keyComponents = append(keyComponents, q.Bytes())
	return keyComponents, nil
}

func DeserializeRsaPrivateComponents(keyComponents [][]byte, rsaKey *rsa.PrivateKey) error {
	if len(keyComponents) < 3 {
		return errors.New("Too few key components")
	}
	rsaKey.PublicKey.N = new(big.Int)
	rsaKey.PublicKey.N.SetBytes(keyComponents[0])
	eInt := new(big.Int)
	eInt.SetBytes(keyComponents[1])
	rsaKey.PublicKey.E = int(eInt.Int64())
	rsaKey.D = new(big.Int)
	rsaKey.D.SetBytes(keyComponents[2])
	if len(keyComponents) < 5 {
		return nil
	}
	p := new(big.Int)
	p.SetBytes(keyComponents[3])
	q := new(big.Int)
	q.SetBytes(keyComponents[4])
	rsaKey.Primes = make([]*big.Int, 2)
	rsaKey.Primes[0] = p
	rsaKey.Primes[1] = q
	return nil
}

func SerializeEcdsaPrivateComponents(ecKey *ecdsa.PrivateKey) ([]byte, error) {
	return x509.MarshalECPrivateKey(ecKey)
}

func DeserializeEcdsaPrivateComponents(keyBytes []byte) (*ecdsa.PrivateKey, error) {
	return x509.ParseECPrivateKey(keyBytes)
}

func SerializeRsaPublicComponents(rsaKey *rsa.PublicKey) ([][]byte, error) {
	// should this use return x509.ParsePKIXPublicKey(keyBytes)?
	// mod, e, d
	var keyComponents [][]byte
	if rsaKey.N == nil {
		return nil, errors.New("No modulus")
	}
	keyComponents = append(keyComponents, rsaKey.N.Bytes())
	eInt := big.NewInt(int64(rsaKey.E))
	keyComponents = append(keyComponents, eInt.Bytes())
	return keyComponents, nil
}

func DeserializeRsaPublicComponents(rsaKey *rsa.PublicKey, keyComponents [][]byte) error {
	if len(keyComponents) < 2 {
		return errors.New("Too few key components")
	}
	rsaKey.N = new(big.Int)
	rsaKey.N.SetBytes(keyComponents[0])
	eInt := new(big.Int)
	eInt.SetBytes(keyComponents[1])
	rsaKey.E = int(eInt.Int64())
	return nil
}

func SerializeEcdsaPublicComponents(ecKey *ecdsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(ecKey)
}

func DeserializeEcdsaPublicComponents(keyBytes []byte) (crypto.PrivateKey, error) {
	return x509.ParsePKIXPublicKey(keyBytes)
}

func KeyComponentsFromSigner(s *Signer) ([][]byte, error) {
	var keyComponents [][]byte
	if s.Header.KeyType == nil {
		return nil, errors.New("Empty key type")
	}
	switch *s.Header.KeyType {
	case "rsa1024", "rsa2048", "rsa3072":
		// Serialize modulus, public-exponent, private-exponent, P, Q
		keyComponents, err := SerializeRsaPrivateComponents((s.PrivKey).(*rsa.PrivateKey))
		if err != nil {
			return nil, errors.New("Can't Serialize")
		}
		return keyComponents, nil
	case "ecdsap256", "ecdsap384", "ecdsap521":
		// Serialize
		keyComponent, err := SerializeEcdsaPrivateComponents((s.PrivKey).(*ecdsa.PrivateKey))
		if err != nil {
			return nil, errors.New("Can't Serialize")
		}
		keyComponents = append(keyComponents, keyComponent)
		return keyComponents, nil
	default:
		return nil, errors.New("Unknown signer key")
	}
	return keyComponents, nil
}

func KeyComponentsFromVerifier(v *Verifier) ([][]byte, error) {
	var keyComponents [][]byte
	if v.Header.KeyType == nil {
		return nil, errors.New("Empty key type")
	}
	switch *v.Header.KeyType {
	case "rsa1024-public", "rsa2048-public", "rsa3072-public":
		// Serialize modulus, public-exponent, private-exponent, P, Q
		keyComponents, err := SerializeRsaPublicComponents((v.PubKey).(*rsa.PublicKey))
		if err != nil {
			return nil, errors.New("Can't Serialize")
		}
		return keyComponents, nil
	case "ecdsap256-public", "ecdsap384-public", "ecdsap521-public":
		// Serialize
		keyComponent, err := SerializeEcdsaPublicComponents((v.PubKey).(*ecdsa.PublicKey))
		if err != nil {
			return nil, errors.New("Can't Serialize")
		}
		keyComponents = append(keyComponents, keyComponent)
		return keyComponents, nil
	default:
	}
	return keyComponents, nil
}

func KeyComponentsFromCrypter(c *Crypter) ([][]byte, error) {
	var keyComponents [][]byte
	if c.Header.KeyType == nil {
		return nil, errors.New("Empty key type")
	}
	switch *c.Header.KeyType {
	case "aes128-ctr-hmacsha256", "aes256-ctr-hmacsha384", "aes256-ctr-hmacsha512":
		keyComponents = append(keyComponents, c.EncryptingKeyBytes)
		keyComponents = append(keyComponents, c.HmacKeyBytes)
	default:
		return nil, errors.New("Unknown crypter key")
	}
	return keyComponents, nil
}

func KeyComponentsFromDeriver(d *Deriver) ([][]byte, error) {
	var keyComponents [][]byte
	if d.Header.KeyType == nil {
		return nil, errors.New("Empty key type")
	}
	switch *d.Header.KeyType {
	case "hdkf-sha256":
		keyComponents = append(keyComponents, d.Secret)
		return keyComponents, nil
	default:
		return nil, errors.New("Unknown deriver key")
	}
	return keyComponents, nil
}

func PrivateKeyFromCryptoKey(k CryptoKey) (crypto.PrivateKey, error) {
	if k.KeyHeader.KeyType == nil {
		return nil, errors.New("Empty key type")
	}
	switch *k.KeyHeader.KeyType {
	case "rsa1024", "rsa2048", "rsa3072":
		rsaKey := new(rsa.PrivateKey)
		err := DeserializeRsaPrivateComponents(k.KeyComponents, rsaKey)
		if err != nil {
			return nil, errors.New("Can't DeserializeRsaPrivateComponents")
		}
		return crypto.PrivateKey(rsaKey), nil
	case "ecdsap256", "ecdsap384", "ecdsap521":
		ecKey, err := DeserializeEcdsaPrivateComponents(k.KeyComponents[0])
		if err != nil {
			return nil, errors.New("Can't DeserializeEcdsaPrivateComponents")
		}
		return crypto.PrivateKey(ecKey), nil
	default:
	}
	return nil, errors.New("Unsupported key type")
}

func PublicKeyFromCryptoKey(k CryptoKey) (crypto.PublicKey, error) {
	var publicKey crypto.PublicKey
	if k.KeyHeader == nil {
		return nil, errors.New("Empty key header")
	}
	switch *k.KeyHeader.KeyType {
	case "rsa1024-public", "rsa2048-public", "rsa3072-public":
		rsaKey := new(rsa.PublicKey)
		err := DeserializeRsaPublicComponents(rsaKey, k.KeyComponents)
		if err != nil {
			return nil, errors.New("Can't DeserializeRsaPublicComponents")
		}
		publicKey = crypto.PublicKey(rsaKey)
		return publicKey, nil
	case "ecdsap256-public", "ecdsap521-public", "ecdsap384-public":
		ecKey, err := DeserializeEcdsaPublicComponents(k.KeyComponents[0])
		if err != nil {
			return nil, errors.New("Can't DeserializeEcdsaPublicComponents")
		}
		publicKey = crypto.PublicKey(ecKey)
		return publicKey, nil
	default:
		return nil, errors.New("Unsupported key type")
	}
	return publicKey, errors.New("Unsupported key type")
}

func (k *CryptoKey) Clear() {
	for i := 0; i < len(k.KeyComponents); i++ {
		ZeroBytes(k.KeyComponents[i])
	}
}

func (s *Signer) Clear() {
	if (s.PrivKey).(*ecdsa.PrivateKey) != nil {
		// TODO: ZeroBytes([]byte((s.PrivKey).(*ecdsa.PrivateKey)))
	} else if (s.PrivKey).(*rsa.PrivateKey) != nil {
	}
}

func (c *Crypter) Clear() {
	ZeroBytes(c.EncryptingKeyBytes)
	ZeroBytes(c.HmacKeyBytes)
}

func (d *Deriver) Clear() {
	ZeroBytes(d.Secret)
}

func CryptoKeyFromSigner(s *Signer) (*CryptoKey, error) {
	keyComponents, err := KeyComponentsFromSigner(s)
	if err != nil {
		return nil, errors.New("Can't get key components")
	}
	ck := &CryptoKey{
		KeyHeader: s.Header,
	}
	ck.KeyComponents = keyComponents
	return ck, nil
}

func CryptoKeyFromVerifier(v *Verifier) (*CryptoKey, error) {
	keyComponents, err := KeyComponentsFromVerifier(v)
	if err != nil {
		return nil, errors.New("Can't get key components")
	}
	ck := &CryptoKey{
		KeyHeader: v.Header,
	}
	ck.KeyComponents = keyComponents
	return ck, nil
}

func CryptoKeyFromCrypter(c *Crypter) (*CryptoKey, error) {
	keyComponents, err := KeyComponentsFromCrypter(c)
	if err != nil {
		return nil, errors.New("Can't get key components")
	}
	ck := &CryptoKey{
		KeyHeader: c.Header,
	}
	ck.KeyComponents = keyComponents
	return ck, nil
}

func CryptoKeyFromDeriver(d *Deriver) (*CryptoKey, error) {
	keyComponents, err := KeyComponentsFromDeriver(d)
	if err != nil {
		return nil, errors.New("Can't get key components")
	}
	ck := &CryptoKey{
		KeyHeader: d.Header,
	}
	ck.KeyComponents = keyComponents
	return ck, nil
}

func PrintCryptoKeyHeader(header CryptoHeader) {
	if header.Version == nil || *header.Version != CryptoVersion_CRYPTO_VERSION_2 {
		fmt.Printf("Wrong version\n")
	}
	if header.KeyName == nil {
		fmt.Printf("No key name\n")
	} else {
		fmt.Printf("Key name: %s\n", *header.KeyName)
	}
	if header.KeyType == nil {
		fmt.Printf("No key type\n")
	} else {
		fmt.Printf("Key type: %s\n", *header.KeyType)
	}
	if header.KeyPurpose == nil {
		fmt.Printf("No Purpose\n")
	} else {
		fmt.Printf("Purpose: %s\n", *header.KeyPurpose)
	}
	if header.KeyStatus == nil {
		fmt.Printf("No key status\n")
	} else {
		fmt.Printf("Key status: %s\n", *header.KeyStatus)
	}
}

func PrintCryptoKey(cryptoKey *CryptoKey) {
	if cryptoKey.KeyHeader == nil {
		fmt.Printf("No key header\n")
		return
	}
	PrintCryptoKeyHeader(*cryptoKey.KeyHeader)
	n := len(cryptoKey.KeyComponents)
	for i := 0; i < n; i++ {
		fmt.Printf("Component %d: %x\n", i, cryptoKey.KeyComponents[i])
	}
}

func MarshalCryptoKey(ck CryptoKey) []byte {
	b, err := proto.Marshal(&ck)
	if err != nil {
		return nil
	}
	return b
}

func UnmarshalCryptoKey(bytes []byte) (*CryptoKey, error) {
	ck := new(CryptoKey)
	err := proto.Unmarshal(bytes, ck)
	if err != nil {
		return nil, err
	}
	return ck, nil
}

func GenerateCryptoKey(keyType string, keyName *string, keyEpoch *int32, keyPurpose *string, keyStatus *string) *CryptoKey {
	cryptoKey := new(CryptoKey)
	switch keyType {
	case "aes128-raw":
		keyBuf, err := randBytes(16)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyBuf)
	case "aes256-raw":
		keyBuf, err := randBytes(32)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyBuf)
	case "aes128-ctr":
		keyBuf, err := randBytes(16)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyBuf)
		ivBuf, err := randBytes(16)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, ivBuf)
	case "aes256-ctr":
		keyBuf, err := randBytes(32)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyBuf)
		hmacBuf, err := randBytes(32)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, hmacBuf)
	case "aes128-ctr-hmacsha256":
		keyBuf, err := randBytes(16)
		if err != nil {
			return nil
		}
		hmacBuf, err := randBytes(32)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyBuf)
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, hmacBuf)
	case "aes256-ctr-hmacsha384":
		keyBuf, err := randBytes(32)
		if err != nil {
			return nil
		}
		hmacBuf, err := randBytes(48)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyBuf)
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, hmacBuf)
	case "aes256-ctr-hmacsha512":
		keyBuf, err := randBytes(32)
		if err != nil {
			return nil
		}
		hmacBuf, err := randBytes(64)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyBuf)
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, hmacBuf)
	case "hmacsha256":
		keyBuf, err := randBytes(32)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyBuf)
	case "hmacsha384":
		keyBuf, err := randBytes(48)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyBuf)
	case "hmacsha512":
		keyBuf, err := randBytes(64)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyBuf)
	case "rsa1024":
		rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			return nil
		}
		// Serialize modulus, public-exponent, private-exponent, P, Q
		keyComponents, err := SerializeRsaPrivateComponents(rsaKey)
		if err != nil {
			return nil
		}
		for i := 0; i < len(keyComponents); i++ {
			cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyComponents[i])
		}
	case "rsa2048":
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil
		}
		keyComponents, err := SerializeRsaPrivateComponents(rsaKey)
		if err != nil {
			return nil
		}
		for i := 0; i < len(keyComponents); i++ {
			cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyComponents[i])
		}
	case "rsa3072":
		rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return nil
		}
		keyComponents, err := SerializeRsaPrivateComponents(rsaKey)
		if err != nil {
			return nil
		}
		for i := 0; i < len(keyComponents); i++ {
			cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyComponents[i])
		}
	case "ecdsap256":
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil
		}
		keyComponent, err := SerializeEcdsaPrivateComponents(ecKey)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyComponent)
	case "ecdsap384":
		ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil
		}
		keyComponent, err := SerializeEcdsaPrivateComponents(ecKey)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyComponent)
	case "ecdsap521":
		ecKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil
		}
		keyComponent, err := SerializeEcdsaPrivateComponents(ecKey)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyComponent)
	case "hdkf-sha256":
		keyBuf, err := randBytes(32)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyBuf)
	default:
		return nil
	}
	ver := CryptoVersion_CRYPTO_VERSION_2
	ch := &CryptoHeader{
		Version:    &ver,
		KeyName:    keyName,
		KeyEpoch:   keyEpoch,
		KeyType:    &keyType,
		KeyPurpose: keyPurpose,
		KeyStatus:  keyStatus,
	}
	cryptoKey.KeyHeader = ch
	return cryptoKey
}

// A Signer is used to sign and verify signatures
type Signer struct {
	Header *CryptoHeader

	PrivKey crypto.PrivateKey
}

// A Verifier is used to verify signatures.
type Verifier struct {
	Header *CryptoHeader

	PubKey crypto.PublicKey
}

// A Crypter is used to encrypt and decrypt data.
type Crypter struct {
	Header *CryptoHeader

	EncryptingKeyBytes []byte
	HmacKeyBytes       []byte
}

// A Deriver is used to derive key material from a context using HKDF.
type Deriver struct {
	Header *CryptoHeader

	Secret []byte
}

func SignerFromCryptoKey(k CryptoKey) *Signer {
	privateKey, err := PrivateKeyFromCryptoKey(k)
	if err != nil {
		return nil
	}
	if k.KeyHeader.KeyType == nil {
		return nil
	}
	s := &Signer{
		Header:  k.KeyHeader,
		PrivKey: privateKey,
	}
	return s
}

func VerifierFromCryptoKey(k CryptoKey) *Verifier {
	publicKey, err := PublicKeyFromCryptoKey(k)
	if err != nil {
		return nil
	}
	if k.KeyHeader.KeyType == nil {
		return nil
	}
	v := &Verifier{
		Header: k.KeyHeader,
		PubKey: publicKey,
	}
	return v
}

func CrypterFromCryptoKey(k CryptoKey) *Crypter {
	if k.KeyHeader.KeyType == nil {
		return nil
	}
	c := &Crypter{
		Header: k.KeyHeader,
	}
	switch *k.KeyHeader.KeyType {
	case "aes128-ctr", "aes256-ctr":
		c.EncryptingKeyBytes = k.KeyComponents[0]
	case "aes128-gcm", "aes256-gcm",
		"aes128-ctr-hmacsha256", "aes256-ctr-hmacsha384", "aes256-ctr-hmacsha512":
		c.EncryptingKeyBytes = k.KeyComponents[0]
		c.HmacKeyBytes = k.KeyComponents[1]
	case "hmacsha256", "hmacsha384", "hmacsha512":
		c.HmacKeyBytes = k.KeyComponents[1]
	default:
		return nil
	}
	return c
}

func DeriverFromCryptoKey(k CryptoKey) *Deriver {
	d := &Deriver{
		Header: k.KeyHeader,
		Secret: k.KeyComponents[0],
	}
	return d
}

func (s *Signer) GetVerifierFromSigner() *Verifier {
	var pub crypto.PublicKey
	if s.Header.KeyType == nil {
		return nil
	}
	switch *s.Header.KeyType {
	case "rsa1024", "rsa2048", "rsa3072":
		pub = &(s.PrivKey).(*rsa.PrivateKey).PublicKey
		break
	case "ecdsap256", "ecdsap384", "ecdsap521":
		pub = &(s.PrivKey).(*ecdsa.PrivateKey).PublicKey
		break
	default:
		return nil
	}
	newKeyType := *s.Header.KeyType + "-public"
	var newHeader CryptoHeader
	newHeader.Version = s.Header.Version
	newHeader.KeyName = s.Header.KeyName
	newHeader.KeyEpoch = s.Header.KeyEpoch
	newHeader.KeyType = &newKeyType
	strVerifying := "verifying"
	newHeader.KeyPurpose = &strVerifying
	newHeader.KeyStatus = s.Header.KeyStatus
	v := &Verifier{
		Header: &newHeader,
		PubKey: pub,
	}
	return v
}

func VerifierKeyFromCanonicalKeyBytes(vb []byte) (*Verifier, error) {
	publicKey, err := x509.ParsePKIXPublicKey(vb)
	if err != nil {
		return nil, err
	}
	keyName := "Anonymous_verifier"
	keyType := VerifierTypeFromSuiteName(TaoCryptoSuite)
	keyPurpose := "verifying"
	keyStatus := "active"
	keyEpoch := int32(1)
	ch := &CryptoHeader{
		KeyName:    &keyName,
		KeyType:    keyType,
		KeyPurpose: &keyPurpose,
		KeyStatus:  &keyStatus,
		KeyEpoch:   &keyEpoch,
	}
	v := &Verifier{
		Header: ch,
		PubKey: publicKey,
	}
	return v, nil
}

func (v *Verifier) GetVerifierPublicKey() crypto.PublicKey {
	return v.PubKey
}

func (s *Signer) GetSignerPrivateKey() crypto.PrivateKey {
	return s.PrivKey
}

func (v *Verifier) CanonicalKeyBytesFromVerifier() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(v.PubKey)
}

func (s *Signer) CanonicalKeyBytesFromSigner() ([]byte, error) {
	return s.GetVerifierFromSigner().CanonicalKeyBytesFromVerifier()
}

func MakeUniversalKeyNameFromCanonicalBytes(cn []byte) []byte {
	// FIX: Should the algorithm be selected from TaoCryptoSuite
	h := sha256.Sum256(cn)
	return h[0:32]
}

func (s *Signer) UniversalKeyNameFromSigner() ([]byte, error) {
	return s.GetVerifierFromSigner().UniversalKeyNameFromVerifier()
}

func (v *Verifier) UniversalKeyNameFromVerifier() ([]byte, error) {
	kb, err := v.CanonicalKeyBytesFromVerifier()
	if err != nil {
		return nil, err
	}
	return MakeUniversalKeyNameFromCanonicalBytes(kb), nil
}

// ToPrincipal produces a "key" type Prin for this signer. This contains a
// serialized CryptoKey for the public portion of the signing key.
func (s *Signer) ToPrincipal() auth.Prin {
	var empty []byte
	// Note: ToPrincipal returns keybytes not universal name
	data, err := s.CanonicalKeyBytesFromSigner()
	if err != nil {
		return auth.NewKeyPrin(empty)
	}
	return auth.NewKeyPrin(data)
}

// ToPrincipal produces a "key" type Prin for this verifier. This contains a
// hash of a serialized CryptoKey for this key.
func (v *Verifier) ToPrincipal() auth.Prin {
	// Note: ToPrincipal returns keybytes not universal name
	var empty []byte
	data, err := v.CanonicalKeyBytesFromVerifier()
	if err != nil {
		return auth.NewKeyPrin(empty)
	}
	return auth.NewKeyPrin(data)
}

// NewX509Name returns a new pkix.Name.
func NewX509Name(p *X509Details) *pkix.Name {
	return &pkix.Name{
		Country:            []string{p.GetCountry()},
		Organization:       []string{p.GetOrganization()},
		OrganizationalUnit: []string{p.GetOrganizationalUnit()},
		Province:           []string{p.GetState()},
		CommonName:         string(p.GetCommonName()),
	}
}

// PrepareX509Template fills out an X.509 template for use in x509.CreateCertificate.
func PrepareX509Template(pkAlg int, sigAlg int, sn int64, subjectName *pkix.Name) *x509.Certificate {
	return &x509.Certificate{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		Version:            2, // x509v3
		// It's always allowed for self-signed certs to have serial 1.
		SerialNumber: new(big.Int).SetInt64(1),
		Subject:      *subjectName,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1 /* years */, 0 /* months */, 0 /* days */),
		// TODO(tmroeder): I'm not sure which of these I need to make
		// OpenSSL happy.
		KeyUsage:    x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
}

// CreateSelfSignedDER creates a DER representation of a new self-signed
// certificate for the given name.
func (s *Signer) CreateSelfSignedDER(pkAlg int, sigAlg int, sn int64, name *pkix.Name) ([]byte, error) {
	template := PrepareX509Template(pkAlg, sigAlg, sn, name)
	template.BasicConstraintsValid = true
	template.IsCA = true
	template.Issuer = template.Subject
	if s.Header.KeyType == nil {
		return nil, errors.New("No key type")
	}
	var pub interface{}
	switch *s.Header.KeyType {
	case "rsa1024", "rsa2048", "rsa3072":
		pub = &(s.PrivKey).(*rsa.PrivateKey).PublicKey
	case "ecdsap256", "ecdsap384", "ecdsap521":
		pub = &(s.PrivKey).(*ecdsa.PrivateKey).PublicKey
	default:
		return nil, errors.New("Unsupported key type")
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, s.PrivKey)
	if err != nil {
		return nil, err
	}
	return der, nil
}

// CreateSelfSignedX509 creates a self-signed X.509 certificate for the public
// key of this Signer.
func (s *Signer) CreateSelfSignedX509(pkAlg int, sigAlg int, sn int64, name *pkix.Name) (*x509.Certificate, error) {
	template := PrepareX509Template(pkAlg, sigAlg, sn, name)
	template.IsCA = true
	template.BasicConstraintsValid = true
	template.Issuer = template.Subject

	if s.Header.KeyType == nil {
		return nil, errors.New("No key type")
	}
	var pub interface{}
	switch *s.Header.KeyType {
	case "rsa1024", "rsa2048", "rsa3072":
		pub = &(s.PrivKey).(*rsa.PrivateKey).PublicKey
	case "ecdsap256", "ecdsap384", "ecdsap521":
		pub = &(s.PrivKey).(*ecdsa.PrivateKey).PublicKey
	default:
		return nil, errors.New("Unsupported key type")
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, s.PrivKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

// CreateCRL creates a signed X.509 certificate list for revoked certificates.
func (s *Signer) CreateCRL(cert *x509.Certificate, revokedCerts []pkix.RevokedCertificate, now, expiry time.Time) ([]byte, error) {
	if cert == nil {
		return nil, errors.New("Missing issuing certificate required to create CRL.")
	}
	return cert.CreateCRL(rand.Reader, s.PrivKey, revokedCerts, now, expiry)
}

// CreateSignedX509FromTemplate creates a signed X.509 certificate for some other subject's
// key.
func (s *Signer) CreateSignedX509FromTemplate(caCert *x509.Certificate, template *x509.Certificate,
	subjectKey *Verifier, pkAlg int, sigAlg int) (*x509.Certificate, error) {

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, subjectKey.PubKey, s.PrivKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// CreateSignedX509 creates a signed X.509 certificate for some other subject's
// key.
// Should take template as argument.
func (s *Signer) CreateSignedX509(caCert *x509.Certificate, sn int, subjectKey *Verifier,
	pkAlg int, sigAlg int, subjectName *pkix.Name) (*x509.Certificate, error) {
	template := PrepareX509Template(pkAlg, sigAlg, int64(sn), subjectName)
	template.SerialNumber = new(big.Int).SetInt64(int64(sn))
	return s.CreateSignedX509FromTemplate(caCert, template, subjectKey, pkAlg, sigAlg)
}

// Derive uses HKDF with HMAC-SHA256 to derive key bytes in its material
// parameter.
func (d *Deriver) Derive(salt, context, material []byte) error {
	f := hkdf.New(sha256.New, d.Secret, salt, context)
	if _, err := f.Read(material); err != nil {
		return err
	}

	return nil
}

// An ecdsaSignature wraps the two components of the signature from an ECDSA
// private key. This is copied from the Go crypto/x509 source: it just uses a
// simple two-element structure to marshal a DSA signature as ASN.1 in an X.509
// certificate.
type ecdsaSignature struct {
	R, S *big.Int
}

// Sign computes a sigature over the contextualized data, using the
// private key of the signer.
func (s *Signer) Sign(data []byte, context string) ([]byte, error) {

	var sig []byte

	newKeyType := *s.Header.KeyType + "-public"
	newHeader := *s.Header
	newHeader.KeyType = &newKeyType

	b, err := contextualizedSHA256(&newHeader, data, context, sha256.Size)
	if err != nil {
		return nil, err
	}

	// TODO(tmroeder): for compatibility with the C++ version, we should
	// compute ECDSA signatures over hashes truncated to fit in the ECDSA
	// signature.
	if s.Header.KeyType == nil {
		return nil, errors.New("Empty header")
	}
	switch *s.Header.KeyType {
	case "ecdsap256", "ecdsap384", "ecdsap521":
		R, S, err := ecdsa.Sign(rand.Reader, s.PrivKey.(*ecdsa.PrivateKey), b)
		if err != nil {
			return nil, err
		}
		sig, err = asn1.Marshal(ecdsaSignature{R, S})
		if err != nil {
			return nil, err
		}
	case "rsa1024", "rsa2048", "rsa3072":
		// Use PSS?
		// Change sig, err = s.PrivKey.(*rsa.PrivateKey).Sign(rand.Reader, b, nil)
		sig, err = rsa.SignPKCS1v15(rand.Reader, s.PrivKey.(*rsa.PrivateKey), crypto.SHA256, b)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("Unsupported signing algorithm")
	}

	sd := &SignedData{
		Header:    &newHeader,
		Signature: sig,
	}
	return proto.Marshal(sd)
}

// Verify checks a signature over the contextualized data, using the
// public key of the verifier.
func (v *Verifier) Verify(data []byte, context string, sig []byte) (bool, error) {
	// Deserialize the data and extract the CryptoHeader.
	var sd SignedData
	if err := proto.Unmarshal(sig, &sd); err != nil {
		return false, err
	}
	if v == nil || v.Header == nil || v.Header.KeyType == nil || sd.Header == nil || sd.Header.KeyType == nil {
		return false, errors.New("NIL ptr")
	}
	if v.Header.KeyType == nil || sd.Header.KeyType == nil || *v.Header.KeyType != *sd.Header.KeyType {
		return false, errors.New("Wrong signature algorithm")
	}

	switch *v.Header.KeyType {
	case "ecdsap256-public", "ecdsap384-public", "ecdsap521-public":
		var ecSig ecdsaSignature
		// We ignore the first parameter, since we don't mind if there's more
		// data after the signature.
		if _, err := asn1.Unmarshal(sd.Signature, &ecSig); err != nil {
			return false, err
		}
		b, err := contextualizedSHA256(sd.Header, data, context, sha256.Size)
		if err != nil {
			return false, err
		}
		return ecdsa.Verify((v.PubKey).(*ecdsa.PublicKey), b, ecSig.R, ecSig.S), nil
	case "rsa1024-public", "rsa2048-public", "rsa3072-public":
		b, err := contextualizedSHA256(sd.Header, data, context, sha256.Size)
		if err != nil {
			return false, err
		}
		err = rsa.VerifyPKCS1v15((v.PubKey).(*rsa.PublicKey), crypto.SHA256, b, sd.Signature)
		if err == nil {
			return true, nil
		}
		return false, err
	default:
		return false, errors.New("Unsupported signing algorithm")
	}
	return false, nil
}

// MarshalKey serializes a Verifier.
func (v *Verifier) MarshalKey() []byte {
	var ck CryptoKey
	if v.Header == nil || v.Header.KeyType == nil {
		return nil
	}
	ck.KeyHeader = v.Header

	switch *v.Header.KeyType {
	case "ecdsap256", "ecdsap384", "ecdsap521":
		keyComponent, err := SerializeEcdsaPublicComponents((v.PubKey).(*ecdsa.PublicKey))
		if err != nil {
			return nil
		}
		ck.KeyComponents = append(ck.KeyComponents, keyComponent)
		return MarshalCryptoKey(ck)
	default:
		return nil
	}
	return nil
}

// UnmarshalKey deserializes a Verifier.
func UnmarshalKey(material []byte) (*Verifier, error) {
	var ck CryptoKey
	err := proto.Unmarshal(material, &ck)
	if err != nil {
		return nil, errors.New("Can't Unmarshal verifier")
	}
	// make sure its a verifying ecdsa key using sha
	if *ck.KeyHeader.KeyPurpose != "verifying" {
		return nil, errors.New("Not a verifying key")
	}
	v := VerifierFromCryptoKey(ck)
	if v == nil {
		return nil, errors.New("VerifierFromCryptoKey failed")
	}
	return v, nil
}

// SignsForPrincipal returns true when prin is (or is a subprincipal of) this verifier key.
func (v *Verifier) SignsForPrincipal(prin auth.Prin) bool {
	return auth.SubprinOrIdentical(prin, v.ToPrincipal())
}

func IsP256(ecPk *ecdsa.PublicKey) bool {
	// This check is insufficient
	if ecPk.Curve.Params().BitSize == 256 {
		return true
	}
	return false
}

func IsP384(ecPk *ecdsa.PublicKey) bool {
	if ecPk.Curve.Params().BitSize == 384 {
		return true
	}
	return false
}

func IsP521(ecPk *ecdsa.PublicKey) bool {
	if ecPk.Curve.Params().BitSize == 521 {
		return true
	}
	return false
}

// VerifierFromX509 creates a Verifier from an X509 certificate.
func VerifierFromX509(cert *x509.Certificate) (*Verifier, error) {
	keyEpoch := int32(1)
	var keyType *string
	if cert.PublicKeyAlgorithm == x509.ECDSA {
		ecPk := cert.PublicKey.(*ecdsa.PublicKey)
		if IsP256(ecPk) {
			keyType = ptrFromString("ecdsap256-public")
		} else if IsP384(ecPk) {
			keyType = ptrFromString("ecdsap384-public")
		} else if IsP521(ecPk) {
			keyType = ptrFromString("ecdsap384-public")
		} else {
			return nil, errors.New("Unsupported ecdsa key type")
		}
	} else if cert.PublicKeyAlgorithm == x509.RSA {
		rsaPk := cert.PublicKey.(*rsa.PublicKey)
		if rsaPk.N.BitLen() > 1022 && rsaPk.N.BitLen() <= 1024 {
			keyType = ptrFromString("rsa1024-public")
		} else if rsaPk.N.BitLen() > 2046 && rsaPk.N.BitLen() <= 2048 {
			keyType = ptrFromString("rsa2048-public")
		} else if rsaPk.N.BitLen() > 3070 && rsaPk.N.BitLen() <= 3072 {
			keyType = ptrFromString("rsa3072-public")
		} else {
			return nil, errors.New("Unsupported rsa key type")
		}
		return nil, errors.New("RSA not supported in FromX509")
	} else {
		return nil, errors.New("Unsupported PublicKeyAlgorithm")
	}
	h := &CryptoHeader{
		KeyName:    ptrFromString("Anonymous verifying key"),
		KeyType:    keyType,
		KeyPurpose: ptrFromString("verifying"),
		KeyEpoch:   &keyEpoch,
		KeyStatus:  ptrFromString("active"),
	}
	v := &Verifier{
		Header: h,
		PubKey: cert.PublicKey,
	}
	return v, nil
}

// Equals checks to see if the public key in the X.509 certificate matches the
// public key in the verifier.
func (v *Verifier) KeyEqual(cert *x509.Certificate) bool {
	v2, err := VerifierFromX509(cert)
	if err != nil {
		return false
	}

	p := v.ToPrincipal()
	p2 := v2.ToPrincipal()
	return p.Identical(p2)
}

// contextualizeData produces a single string from a header, data, and a context.
func contextualizeData(data []byte, context string) ([]byte, error) {
	s := &ContextualizedData{
		Context: proto.String(context),
		Data:    data,
	}
	return proto.Marshal(s)
}

// contextualizedSHA256 performs a SHA-256 sum over contextualized data.
func contextualizedSHA256(h *CryptoHeader, data []byte, context string, digestLen int) ([]byte, error) {
	b, err := contextualizeData(data, context)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(b)
	return hash[:digestLen], nil
}

// Handles both aes128/sha256 and aes256/sha256
func (c *Crypter) encryptAes128ctrHmacsha256(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.EncryptingKeyBytes)
	if err != nil {
		return nil, err
	}

	// A ciphertext consists of an IV, encrypted bytes, and the output of
	// HMAC-SHA256.
	ciphertext := make([]byte, aes.BlockSize+len(plain))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	s := cipher.NewCTR(block, iv)
	s.XORKeyStream(ciphertext[aes.BlockSize:], plain)

	mac := hmac.New(sha256.New, c.HmacKeyBytes)
	mac.Write(ciphertext)
	m := mac.Sum(nil)

	ed := &EncryptedData{
		Header:     c.Header,
		Iv:         iv,
		Ciphertext: ciphertext[aes.BlockSize:],
		Mac:        m,
	}

	return proto.Marshal(ed)
}

// Handles both aes128/sha256 and aes256/sha256
func (c *Crypter) decryptAes128ctrHmacsha256(ciphertext []byte) ([]byte, error) {
	var ed EncryptedData
	if err := proto.Unmarshal(ciphertext, &ed); err != nil {
		return nil, err
	}
	if *ed.Header.Version != CryptoVersion_CRYPTO_VERSION_2 {
		return nil, errors.New("bad version")
	}
	if ed.Header.KeyType == nil || c.Header.KeyType == nil {
		return nil, errors.New("empty key header")
	}
	if *ed.Header.KeyType != *c.Header.KeyType {
		return nil, errors.New("bad key type")
	}

	// Check the HMAC before touching the ciphertext.
	fullCiphertext := make([]byte, len(ed.Iv)+len(ed.Ciphertext))
	copy(fullCiphertext, ed.Iv)
	copy(fullCiphertext[len(ed.Iv):], ed.Ciphertext)

	mac := hmac.New(sha256.New, c.HmacKeyBytes)
	mac.Write(fullCiphertext)
	m := mac.Sum(nil)
	if !hmac.Equal(m, ed.Mac) {
		return nil, errors.New("bad HMAC")
	}

	block, err := aes.NewCipher(c.EncryptingKeyBytes)
	if err != nil {
		return nil, err
	}

	s := cipher.NewCTR(block, ed.Iv)
	plain := make([]byte, len(ed.Ciphertext))
	s.XORKeyStream(plain, ed.Ciphertext)
	return plain, nil
}

func (c *Crypter) encryptAes256ctrHmacsha512(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.EncryptingKeyBytes)
	if err != nil {
		return nil, err
	}

	// A ciphertext consists of an IV, encrypted bytes, and the output of
	// HMAC-SHA512.
	ciphertext := make([]byte, aes.BlockSize+len(plain))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	s := cipher.NewCTR(block, iv)
	s.XORKeyStream(ciphertext[aes.BlockSize:], plain)

	mac := hmac.New(sha512.New, c.HmacKeyBytes)
	mac.Write(ciphertext)
	m := mac.Sum(nil)

	ed := &EncryptedData{
		Header:     c.Header,
		Iv:         iv,
		Ciphertext: ciphertext[aes.BlockSize:],
		Mac:        m,
	}

	return proto.Marshal(ed)
}

func (c *Crypter) decryptAes256ctrHmacsha512(ciphertext []byte) ([]byte, error) {
	var ed EncryptedData
	if err := proto.Unmarshal(ciphertext, &ed); err != nil {
		return nil, err
	}
	if *ed.Header.Version != CryptoVersion_CRYPTO_VERSION_2 {
		return nil, errors.New("bad version")
	}
	if ed.Header.KeyType == nil || c.Header.KeyType == nil {
		return nil, errors.New("empty key header")
	}
	if *ed.Header.KeyType != "aes256-ctr-hmacsha512" {
		return nil, errors.New("bad key type")
	}

	// Check the HMAC before touching the ciphertext.
	fullCiphertext := make([]byte, len(ed.Iv)+len(ed.Ciphertext))
	copy(fullCiphertext, ed.Iv)
	copy(fullCiphertext[len(ed.Iv):], ed.Ciphertext)

	mac := hmac.New(sha512.New, c.HmacKeyBytes)
	mac.Write(fullCiphertext)
	m := mac.Sum(nil)
	if !hmac.Equal(m, ed.Mac) {
		return nil, errors.New("bad HMAC")
	}

	block, err := aes.NewCipher(c.EncryptingKeyBytes)
	if err != nil {
		return nil, err
	}

	s := cipher.NewCTR(block, ed.Iv)
	plain := make([]byte, len(ed.Ciphertext))
	s.XORKeyStream(plain, ed.Ciphertext)
	return plain, nil
}

func (c *Crypter) encryptAes256ctrHmacsha384(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.EncryptingKeyBytes)
	if err != nil {
		return nil, err
	}

	// A ciphertext consists of an IV, encrypted bytes, and the output of
	// HMAC-SHA384.
	ciphertext := make([]byte, aes.BlockSize+len(plain))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	s := cipher.NewCTR(block, iv)
	s.XORKeyStream(ciphertext[aes.BlockSize:], plain)

	mac := hmac.New(sha512.New384, c.HmacKeyBytes)
	mac.Write(ciphertext)
	m := mac.Sum(nil)

	ed := &EncryptedData{
		Header:     c.Header,
		Iv:         iv,
		Ciphertext: ciphertext[aes.BlockSize:],
		Mac:        m,
	}

	return proto.Marshal(ed)
}

func (c *Crypter) decryptAes256ctrHmacsha384(ciphertext []byte) ([]byte, error) {
	var ed EncryptedData
	if err := proto.Unmarshal(ciphertext, &ed); err != nil {
		return nil, err
	}
	if *ed.Header.Version != CryptoVersion_CRYPTO_VERSION_2 {
		return nil, errors.New("bad version")
	}
	if ed.Header.KeyType == nil || c.Header.KeyType == nil {
		return nil, errors.New("empty key header")
	}
	if *ed.Header.KeyType != "aes256-ctr-hmacsha384" {
		return nil, errors.New("bad key type")
	}

	// Check the HMAC before touching the ciphertext.
	fullCiphertext := make([]byte, len(ed.Iv)+len(ed.Ciphertext))
	copy(fullCiphertext, ed.Iv)
	copy(fullCiphertext[len(ed.Iv):], ed.Ciphertext)

	mac := hmac.New(sha512.New384, c.HmacKeyBytes)
	mac.Write(fullCiphertext)
	m := mac.Sum(nil)
	if !hmac.Equal(m, ed.Mac) {
		return nil, errors.New("bad HMAC")
	}

	block, err := aes.NewCipher(c.EncryptingKeyBytes)
	if err != nil {
		return nil, err
	}

	s := cipher.NewCTR(block, ed.Iv)
	plain := make([]byte, len(ed.Ciphertext))
	s.XORKeyStream(plain, ed.Ciphertext)
	return plain, nil
}

// Encrypt encrypts plaintext into ciphertext with integrity
// with a MAC.
func (c *Crypter) Encrypt(plain []byte) ([]byte, error) {
	if c == nil || c.Header == nil || c.Header.KeyType == nil {
		return nil, errors.New("Key Type not set")
	}
	switch *c.Header.KeyType {
	case "aes128-ctr-hmacsha256":
		return c.encryptAes128ctrHmacsha256(plain)
	case "aes256-ctr-hmacsha384":
		return c.encryptAes256ctrHmacsha384(plain)
	case "aes256-ctr-hmacsha512":
		return c.encryptAes256ctrHmacsha512(plain)
	default:
		return nil, errors.New("Unsupported crypting algorithm")
	}
}

// Decrypt checks the MAC then decrypts ciphertext into plaintext.
func (c *Crypter) Decrypt(ciphertext []byte) ([]byte, error) {
	if c.Header.KeyType == nil {
		return nil, errors.New("Key Type not set")
	}
	switch *c.Header.KeyType {
	case "aes128-ctr-hmacsha256":
		return c.decryptAes128ctrHmacsha256(ciphertext)
	case "aes256-ctr-hmacsha384":
		return c.decryptAes256ctrHmacsha384(ciphertext)
	case "aes256-ctr-hmacsha512":
		return c.decryptAes256ctrHmacsha512(ciphertext)
	default:
		return nil, errors.New("Unsupported crypting algorithm")
	}
}

// This code is duplicated in VerifierFromCanonicalBytes
// MarshalSignerDER serializes the signer to DER.
func MarshalSignerDER(s *Signer) ([]byte, error) {
	// TODO: only ecdsa is supported, but this code is redundant now.
	if s.Header.KeyType == nil {
		return nil, errors.New("Unsupported alg for MarshalSignerDER")
	}
	switch *s.Header.KeyType {
	case "ecdsap256", "ecdsap384", "ecdsap521":
		return x509.MarshalECPrivateKey((s.PrivKey).(*ecdsa.PrivateKey))
	default:
		return nil, errors.New("Unsupported alg for MarshalSignerDER")
	}
	return nil, errors.New("Unsupported alg for MarshalSignerDER")
}

// UnmarshalSignerDER deserializes a Signer from DER.
func UnmarshalSignerDER(signer []byte) (*Signer, error) {
	// TODO: only ecdsa is supported
	keyName := "Unnamed ECDSA signer"
	keyEpoch := int32(1)
	keyType := "ecdsap256"
	keyPurpose := "singing"
	keyStatus := "active"
	h := &CryptoHeader{
		KeyName:    &keyName,
		KeyEpoch:   &keyEpoch,
		KeyType:    &keyType,
		KeyPurpose: &keyPurpose,
		KeyStatus:  &keyStatus,
	}
	k := &Signer{
		Header: h,
	}
	privateKey, err := x509.ParseECPrivateKey(signer)
	if err != nil {
		return nil, err
	}
	k.PrivKey = privateKey
	return k, nil
}

func GenerateAnonymousSigner() *Signer {
	keyName := "Anonymous_signer"
	keyType := SignerTypeFromSuiteName(TaoCryptoSuite)
	if keyType == nil {
		return nil
	}
	keyPurpose := "signing"
	keyStatus := "active"
	keyEpoch := int32(1)
	s, err := InitializeSigner(nil, *keyType, &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if err != nil {
		return nil
	}
	return s
}

func GenerateAnonymousCrypter() *Crypter {
	keyName := "Anonymous_crypter"
	keyType := CrypterTypeFromSuiteName(TaoCryptoSuite)
	keyPurpose := "crypting"
	keyStatus := "active"
	keyEpoch := int32(1)
	c, err := InitializeCrypter(nil, *keyType, &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if err != nil {
		return nil
	}
	return c
}

func GenerateAnonymousDeriver() *Deriver {
	keyName := "Anonymous_deriver"
	keyType := DeriverTypeFromSuiteName(TaoCryptoSuite)
	keyPurpose := "deriving"
	keyStatus := "active"
	keyEpoch := int32(1)
	d, err := InitializeDeriver(nil, *keyType, &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if err != nil {
		return nil
	}
	return d
}

func Protect(keys []byte, in []byte) ([]byte, error) {
	keyType := CrypterTypeFromSuiteName(TaoCryptoSuite)
	if keyType == nil {
		return nil, errors.New("Protect: Can't get key type from cipher suite")
	}
	encKeySize := SymmetricKeySizeFromAlgorithmName(*keyType)
	if encKeySize == nil {
		return nil, errors.New("Protect: Can't get symmetric key size from key type")
	}
	totalKeySize := CombinedKeySizeFromAlgorithmName(*keyType)
	if totalKeySize == nil {
		return nil, errors.New("Protect: Can't get total key size from key type")
	}
	if *totalKeySize > len(keys) {
		return nil, errors.New("Protect: Bad key size")
	}
	blkSize := SymmetricBlockSizeFromAlgorithmName(*keyType)
	if blkSize == nil {
		return nil, errors.New("Protect: Can't get block size from key type")
	}
	if in == nil {
		return nil, nil
	}
	if len(keys) < *totalKeySize {
		return nil, errors.New("Protect: Supplied key size too small")
	}
	iv := make([]byte, *blkSize, *blkSize)
	_, err := rand.Read(iv[0:*blkSize])
	if err != nil {
		return nil, errors.New("Protect: Can't generate iv")
	}
	encKey := keys[0:*encKeySize]
	macKey := keys[*encKeySize:*totalKeySize]
	crypter, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, errors.New("Protect: Can't make crypter")
	}
	ctr := cipher.NewCTR(crypter, iv)
	cipheredOut := make([]byte, len(in))
	ctr.XORKeyStream(cipheredOut, in)
	ivAndCiphered := append(iv, cipheredOut...)

	var calculatedHmac []byte
	switch *keyType {
	default:
		return nil, errors.New("unknown symmetric cipher suite")
	case "aes128-ctr-hmacsha256":
		hm := hmac.New(sha256.New, macKey)
		hm.Write(ivAndCiphered)
		calculatedHmac = hm.Sum(nil)
	case "aes256-ctr-hmacsha384":
		hm := hmac.New(sha512.New384, macKey)
		hm.Write(ivAndCiphered)
		calculatedHmac = hm.Sum(nil)
	case "aes256-ctr-hmacsha512":
		hm := hmac.New(sha512.New, macKey)
		hm.Write(ivAndCiphered)
		calculatedHmac = hm.Sum(nil)
	}
	return append(calculatedHmac, ivAndCiphered...), nil
}

func Unprotect(keys []byte, in []byte) ([]byte, error) {
	keyType := CrypterTypeFromSuiteName(TaoCryptoSuite)
	if keyType == nil {
		return nil, errors.New("Unprotect: Can't get key type from cipher suite")
	}
	encKeySize := SymmetricKeySizeFromAlgorithmName(*keyType)
	if encKeySize == nil {
		return nil, errors.New("Unprotect: Can't get symmetric key size from key type")
	}
	hmacKeySize := HmacKeySizeFromAlgorithmName(*keyType)
	if hmacKeySize == nil {
		return nil, errors.New("Unprotect: Can't get hmac key size from key type")
	}
	hmacSize := HmacKeySizeFromAlgorithmName(*keyType)
	if hmacSize == nil {
		return nil, errors.New("Unprotect: Can't get hmac size from key type")
	}
	totalKeySize := CombinedKeySizeFromAlgorithmName(*keyType)
	if totalKeySize == nil {
		return nil, errors.New("Unprotect: Can't get total key size from key type")
	}
	if *totalKeySize > len(keys) {
		return nil, errors.New("Unprotect: Bad key size")
	}
	blkSize := SymmetricBlockSizeFromAlgorithmName(*keyType)
	if blkSize == nil {
		return nil, errors.New("Unprotect: Can't get block size from key type")
	}
	if in == nil {
		return nil, nil
	}
	out := make([]byte, len(in)-*blkSize-*hmacSize, len(in)-*blkSize-*hmacSize)
	iv := in[*hmacSize : *hmacSize+*blkSize]
	encKey := keys[0:*encKeySize]
	macKey := keys[*encKeySize:*totalKeySize]
	crypter, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, errors.New("Unprotect: Can't make crypter")
	}
	ctr := cipher.NewCTR(crypter, iv)
	ctr.XORKeyStream(out, in[*hmacSize+*blkSize:])

	var calculatedHmac []byte
	switch *keyType {
	default:
		return nil, errors.New("unknown symmetric cipher suite")
	case "aes128-ctr-hmacsha256":
		hm := hmac.New(sha256.New, macKey)
		hm.Write(in[*hmacSize:])
		calculatedHmac = hm.Sum(nil)
	case "aes256-ctr-hmacsha384":
		hm := hmac.New(sha512.New384, macKey)
		hm.Write(in[*hmacSize:])
		calculatedHmac = hm.Sum(nil)
	case "aes256-ctr-hmacsha512":
		hm := hmac.New(sha512.New, macKey)
		hm.Write(in[*hmacSize:])
		calculatedHmac = hm.Sum(nil)
	}
	if bytes.Compare(calculatedHmac, in[0:*hmacSize]) != 0 {
		return nil, errors.New("Unprotect: Bad mac")
	}
	return out, nil
}
