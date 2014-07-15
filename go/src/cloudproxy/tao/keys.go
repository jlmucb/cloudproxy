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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"path"
	"time"

	"code.google.com/p/goprotobuf/proto"
)

// A KeyType represent the type(s) of keys held by a Keys struct.
type KeyType int

const (
	Signing     KeyType = 1 << iota
	Crypting
	KeyDeriving
)

// A Signer is used to sign and verify signatures
type Signer struct {
	ec *ecdsa.PrivateKey
}

// A Verifier is used to verify signatures.
// TODO(tmroeder): implement the Verifier over basic Go crypto.
type Verifier struct {
	ec *ecdsa.PublicKey
}

// TODO(tmroeder): implement the Crypter over basic Go crypto.
type Crypter struct {

}

// A Deriver is used to derive key material from a context using PBDKF2.
// TODO(tmroeder): implement the deriver over basic Go crypto
type Deriver struct {

}

// GenerateSigner creates a new Signer with a fresh key.
func GenerateSigner() (*Signer, error) {
	k := new(Signer)

	var err error
	if k.ec, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, err
	}

	return k, nil
}

// ToPrincipalName produces a plain-text Tao principal name. This is a
// base64w-encoded version of a serialized CryptoKey for the public half of
// this signing key.
func (s *Signer) ToPrincipalName() (string, error) {
	var ck *CryptoKey
	var err error
	if ck, err = MarshalPublicSignerProto(s); err != nil {
		return "", nil
	}

	data, err := proto.Marshal(ck)
	if err != nil {
		return "", err
	}

	return "Key(" + base64.URLEncoding.EncodeToString(data) + ")", nil
}

// MarshalSigner serializes the signer to PEM.
func MarshalSignerPEM(s *Signer) ([]byte, error) {
	return x509.MarshalECPrivateKey(s.ec)
}

// ParseSigner deserializes a Signer from PEM.
func ParseSignerPEM(signer []byte) (*Signer, error) {
	k := new(Signer)
	var err error
	if k.ec, err = x509.ParseECPrivateKey(signer); err != nil {
		return nil, err
	}

	return k, nil
}

// prepareX509Template parses the protobuf containing subject-name details and
// fills out an X.509 template for use in x509.CreateCertificate.
func prepareX509Template(detailsText string) (*x509.Certificate, error) {
	details := new(X509Details)
	if err := proto.UnmarshalText(detailsText, details); err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		Version: 2, // x509v3
		// It's always allowed for self-signed certs to have serial 1.
		SerialNumber: new(big.Int).SetInt64(1),
		Subject: pkix.Name{
			Country: []string{string(details.Country)},
			Organization: []string{string(details.Organization)},
			Province: []string{string(details.State)},
			CommonName: string(details.Commonname),
		},
		NotBefore: time.Now(),
		NotAfter: time.Now().AddDate(1 /* years */ , 0 /* months */, 0 /* days */),
		// TODO(tmroeder): I'm not sure which of these I need to make
		// OpenSSL happy.
		KeyUsage: x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	return template, nil
}

// CreateSelfSignedX509 creates a self-signed X.509 certificate for the public
// key of this Signer.
func (s *Signer) CreateSelfSignedX509(detailsText string) ([]byte, error) {
	template, err := prepareX509Template(detailsText)
	if err != nil {
		return nil, err
	}

	template.IsCA = true
	template.Issuer = template.Subject

	return x509.CreateCertificate(rand.Reader, template, template, &s.ec.PublicKey, s.ec)
}

// CreateSignedX509 creates a signed X.509 certificate for some other subject's
// key.
func (s *Signer) CreateSignedX509(CAPEMCert []byte, certSerial int, subjectKey *Verifier, subjectDetails string) ([]byte, error) {
	signerCert, err := x509.ParseCertificate(CAPEMCert)
	if err != nil {
		return nil, err
	}

	template, err := prepareX509Template(subjectDetails)
	if err != nil {
		return nil, err
	}

	return x509.CreateCertificate(rand.Reader, template, signerCert, subjectKey.ec, s.ec)
}

// marshalECDSA_SHA_SigningKeyV1 encodes a private key as a protobuf message.
func marshalECDSA_SHA_SigningKeyV1(k *ecdsa.PrivateKey) *ECDSA_SHA_SigningKeyV1 {
	return &ECDSA_SHA_SigningKeyV1{
		Curve: NamedEllipticCurve_PRIME256_V1.Enum(),
		EcPrivate: k.D.Bytes(),
		EcPublic: elliptic.Marshal(k.Curve, k.X, k.Y),
	}

}

// MarshalSignerProto encodes a signing key as a CryptoKey protobuf message.
func MarshalSignerProto(s *Signer) (*CryptoKey, error) {
	m := marshalECDSA_SHA_SigningKeyV1(s.ec)
	defer zeroBytes(m.EcPrivate)

	b, err := proto.Marshal(m)
	if err != nil {
		return nil, err
	}

	ck := &CryptoKey{
		Version: CryptoVersion_CRYPTO_VERSION_1.Enum(),
		Purpose: CryptoKey_SIGNING.Enum(),
		Algorithm: CryptoKey_ECDSA_SHA.Enum(),
		Key: b,
	}

	return ck, nil
}

// marshalECDSA_SHA_VerifyingKeyV1 encodes a public key as a protobuf message.
func marshalECDSA_SHA_VerifyingKeyV1(k *ecdsa.PublicKey) *ECDSA_SHA_VerifyingKeyV1 {
	return &ECDSA_SHA_VerifyingKeyV1{
		Curve: NamedEllipticCurve_PRIME256_V1.Enum(),
		EcPublic: elliptic.Marshal(k.Curve, k.X, k.Y),
	}

}

// MarshalPublicSignerProto encodes the public half of a signing key as a
// CryptoKey protobuf message.
func MarshalPublicSignerProto(s *Signer) (*CryptoKey, error) {
	m := marshalECDSA_SHA_VerifyingKeyV1(&s.ec.PublicKey)

	b, err := proto.Marshal(m)
	if err != nil {
		return nil, err
	}

	ck := &CryptoKey{
		Version: CryptoVersion_CRYPTO_VERSION_1.Enum(),
		Purpose: CryptoKey_VERIFYING.Enum(),
		Algorithm: CryptoKey_ECDSA_SHA.Enum(),
		Key: b,
	}

	return ck, nil
}

// UnmarshalSignerProto decodes a signing key from a CryptoKey protobuf
// message.
func UnmarshalSignerProto(ck *CryptoKey) (*Signer, error) {
	if *ck.Version != CryptoVersion_CRYPTO_VERSION_1 {
		return nil, errors.New("Bad version")
	}

	if *ck.Purpose != CryptoKey_SIGNING {
		return nil, errors.New("Bad purpose")
	}

	if *ck.Algorithm != CryptoKey_ECDSA_SHA {
		return nil, errors.New("Bad algorithm")
	}

	k := new(ECDSA_SHA_SigningKeyV1)
	defer zeroBytes(k.EcPrivate)
	if err := proto.Unmarshal(ck.Key, k); err != nil {
		return nil, err
	}

	if *k.Curve != NamedEllipticCurve_PRIME256_V1 {
		return nil, errors.New("Bad Curve")
	}

	s := new(Signer)
	s.ec = new(ecdsa.PrivateKey)
	s.ec.D = new(big.Int).SetBytes(k.EcPrivate)
	s.ec.X, s.ec.Y = elliptic.Unmarshal(elliptic.P256(), k.EcPublic)
	return s, nil
}

// FillHeader encodes the version and a key hint into a CryptoHeader.
func (s *Signer) CreateHeader() (*CryptoHeader, error) {
	k := marshalECDSA_SHA_VerifyingKeyV1(&s.ec.PublicKey)
	b, err := proto.Marshal(k)
	if err != nil {
		return nil, err
	}

	h := sha1.Sum(b)
	ch := &CryptoHeader{
		Version: CryptoVersion_CRYPTO_VERSION_1.Enum(),
		KeyHint: h[:4],
	}

	return ch, nil
}

// GetECDSAKey returns the private ECDSA key for this signer.
func (s *Signer) getECDSAKey() *ecdsa.PrivateKey {
	return s.ec
}


// A Keys holds a set of Keyczar keys and provides an interface to perform
// actions with these keys.
type Keys struct {
	dir string
	policy string

	signer *Signer
	crypter *Crypter
	verifer *Verifier
	deriver *Deriver
	delegation *Attestation
	cert *x509.Certificate
}

// SignerPath returns the path to the signing keys, if any.
func (k *Keys) SignerPath() string {
	if k.dir == "" {
		return ""
	} else {
		return path.Join(k.dir, "signer")
	}
}

// CrypterPath returns the path to the encryption key, if any.
func (k *Keys) CrypterPath() string {
	if k.dir == "" {
		return ""
	} else {
		return path.Join(k.dir, "crypter")
	}
}

// KeyDeriverPath returns the path to the key-deriving key, if any.
func (k *Keys) KeyDeriverPath() string {
	if k.dir == "" {
		return ""
	} else {
		return path.Join(k.dir, "key_deriver")
	}
}

// TaoSecretPath returns the path to a Tao-sealed secret, if any. This secret
// is used to create a PBEEncrypter to encrypt generated keys.
func (k *Keys) TaoSecretPath() string {
	if k.dir == "" {
		return ""
	} else {
		return path.Join(k.dir, "secret")
	}
}

// zeroBytes clears the bytes in a slice.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
