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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"time"

	"code.google.com/p/go.crypto/hkdf"
	"code.google.com/p/go.crypto/pbkdf2"
	"code.google.com/p/goprotobuf/proto"

	"github.com/jlmucb/cloudproxy/tao/auth"
	"github.com/jlmucb/cloudproxy/util"
)

// A KeyType represent the type(s) of keys held by a Keys struct.
type KeyType int

// These are the types of supported keys.
const (
	Signing KeyType = 1 << iota
	Crypting
	Deriving
)

const aesKeySize = 32 // 256-bit AES
const deriverSecretSize = 32
const hmacKeySize = 32 // SHA-256

// A Signer is used to sign and verify signatures
type Signer struct {
	ec *ecdsa.PrivateKey
}

// A Verifier is used to verify signatures.
type Verifier struct {
	ec *ecdsa.PublicKey
}

// A Crypter is used to encrypt and decrypt data.
type Crypter struct {
	aesKey  []byte
	hmacKey []byte
}

// A Deriver is used to derive key material from a context using HKDF.
type Deriver struct {
	secret []byte
}

// GenerateSigner creates a new Signer with a fresh key.
func GenerateSigner() (*Signer, error) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Signer{ec}, nil
}

// ToPrincipal produces a "key" type Prin for this signer. This contains a
// serialized CryptoKey for the public half of this signing key.
func (s *Signer) ToPrincipal() auth.Prin {
	ck := MarshalPublicSignerProto(s)

	// proto.Marshal won't fail here since we fill all required fields of the
	// message. Propagating impossible errors just leads to clutter later.
	data, _ := proto.Marshal(ck)

	return auth.NewKeyPrin(data)
}

// MarshalSignerDER serializes the signer to DER.
func MarshalSignerDER(s *Signer) ([]byte, error) {
	return x509.MarshalECPrivateKey(s.ec)
}

// UnmarshalSignerDER deserializes a Signer from DER.
func UnmarshalSignerDER(signer []byte) (*Signer, error) {
	k := new(Signer)
	var err error
	if k.ec, err = x509.ParseECPrivateKey(signer); err != nil {
		return nil, err
	}

	return k, nil
}

// X509Details is a simplified version of pkix.Name, suitable for most purposes.
// All of the fields are optional.
type X509Details struct {
	CommonName, Country, State, Organization, OrganizationalUnit string
}

// NewX509Name returns a new pkix.Name.
func NewX509Name(p X509Details) *pkix.Name {
	return &pkix.Name{
		Country:            []string{string(p.Country)},
		Organization:       []string{string(p.Organization)},
		OrganizationalUnit: []string{string(p.OrganizationalUnit)},
		Province:           []string{string(p.State)},
		CommonName:         string(p.CommonName),
	}
}

// prepareX509Template fills out an X.509 template for use in x509.CreateCertificate.
func prepareX509Template(subjectName *pkix.Name) *x509.Certificate {
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
		KeyUsage:    x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
}

func (s *Signer) CreateSelfSignedDER(name *pkix.Name) ([]byte, error) {
	template := prepareX509Template(name)
	template.BasicConstraintsValid = true
	template.IsCA = true
	template.Issuer = template.Subject
	der, err := x509.CreateCertificate(rand.Reader, template, template, &s.ec.PublicKey, s.ec)
	if err != nil {
		return nil, err
	}
	return der, nil
}

// CreateSelfSignedX509 creates a self-signed X.509 certificate for the public
// key of this Signer.
func (s *Signer) CreateSelfSignedX509(name *pkix.Name) (*x509.Certificate, error) {
	template := prepareX509Template(name)
	template.IsCA = true
	template.BasicConstraintsValid = true
	template.Issuer = template.Subject

	der, err := x509.CreateCertificate(rand.Reader, template, template, &s.ec.PublicKey, s.ec)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

// CreateSignedX509 creates a signed X.509 certificate for some other subject's
// key.
func (s *Signer) CreateSignedX509(caCert *x509.Certificate, certSerial int, subjectKey *Verifier, subjectName *pkix.Name) (*x509.Certificate, error) {
	template := prepareX509Template(subjectName)
	template.SerialNumber = new(big.Int).SetInt64(int64(certSerial))

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, subjectKey.ec, s.ec)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// marshalECDSA_SHA_SigningKeyV1 encodes a private key as a protobuf message.
func marshalECDSA_SHA_SigningKeyV1(k *ecdsa.PrivateKey) *ECDSA_SHA_SigningKeyV1 {
	return &ECDSA_SHA_SigningKeyV1{
		Curve:     NamedEllipticCurve_PRIME256_V1.Enum(),
		EcPrivate: k.D.Bytes(),
		EcPublic:  elliptic.Marshal(k.Curve, k.X, k.Y),
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
		Version:   CryptoVersion_CRYPTO_VERSION_1.Enum(),
		Purpose:   CryptoKey_SIGNING.Enum(),
		Algorithm: CryptoKey_ECDSA_SHA.Enum(),
		Key:       b,
	}
	return ck, nil
}

// marshalECDSA_SHA_VerifyingKeyV1 encodes a public key as a protobuf message.
func marshalECDSA_SHA_VerifyingKeyV1(k *ecdsa.PublicKey) *ECDSA_SHA_VerifyingKeyV1 {
	return &ECDSA_SHA_VerifyingKeyV1{
		Curve:    NamedEllipticCurve_PRIME256_V1.Enum(),
		EcPublic: elliptic.Marshal(k.Curve, k.X, k.Y),
	}

}

func unmarshalECDSA_SHA_VerifyingKeyV1(v *ECDSA_SHA_VerifyingKeyV1) (*ecdsa.PublicKey, error) {
	if *v.Curve != NamedEllipticCurve_PRIME256_V1 {
		return nil, newError("bad curve")
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), v.EcPublic)
	pk := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
	return pk, nil
}

func marshalPublicKeyProto(k *ecdsa.PublicKey) *CryptoKey {
	m := marshalECDSA_SHA_VerifyingKeyV1(k)

	// proto.Marshal won't fail here since we fill all required fields of the
	// message. Propagating impossible errors just leads to clutter later.
	b, _ := proto.Marshal(m)

	return &CryptoKey{
		Version:   CryptoVersion_CRYPTO_VERSION_1.Enum(),
		Purpose:   CryptoKey_VERIFYING.Enum(),
		Algorithm: CryptoKey_ECDSA_SHA.Enum(),
		Key:       b,
	}
}

// MarshalPublicSignerProto encodes the public half of a signing key as a
// CryptoKey protobuf message.
func MarshalPublicSignerProto(s *Signer) *CryptoKey {
	return marshalPublicKeyProto(&s.ec.PublicKey)
}

// MarshalVerifierProto encodes the public verifier key as a CryptoKey protobuf
// message.
func MarshalVerifierProto(v *Verifier) *CryptoKey {
	return marshalPublicKeyProto(v.ec)
}

// UnmarshalSignerProto decodes a signing key from a CryptoKey protobuf
// message.
func UnmarshalSignerProto(ck *CryptoKey) (*Signer, error) {
	if *ck.Version != CryptoVersion_CRYPTO_VERSION_1 {
		return nil, newError("bad version")
	}

	if *ck.Purpose != CryptoKey_SIGNING {
		return nil, newError("bad purpose")
	}

	if *ck.Algorithm != CryptoKey_ECDSA_SHA {
		return nil, newError("bad algorithm")
	}

	k := new(ECDSA_SHA_SigningKeyV1)
	defer zeroBytes(k.EcPrivate)
	if err := proto.Unmarshal(ck.Key, k); err != nil {
		return nil, err
	}

	if *k.Curve != NamedEllipticCurve_PRIME256_V1 {
		return nil, newError("bad Curve")
	}

	s := new(Signer)
	s.ec = new(ecdsa.PrivateKey)
	s.ec.D = new(big.Int).SetBytes(k.EcPrivate)
	s.ec.Curve = elliptic.P256()
	s.ec.X, s.ec.Y = elliptic.Unmarshal(elliptic.P256(), k.EcPublic)
	return s, nil
}

// CreateHeader encodes the version and a key hint into a CryptoHeader.
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

// An ecdsaSignature wraps the two components of the signature from an ECDSA
// private key. This is copied from the Go crypto/x509 source: it just uses a
// simple two-element structure to marshal a DSA signature as ASN.1 in an X.509
// certificate.
type ecdsaSignature struct {
	R, S *big.Int
}

// Sign computes an ECDSA sigature over the contextualized data, using the
// private key of the signer.
func (s *Signer) Sign(data []byte, context string) ([]byte, error) {
	ch, err := s.CreateHeader()
	if err != nil {
		return nil, err
	}

	// TODO(tmroeder): for compatibility with the C++ version, we should
	// compute ECDSA signatures over hashes truncated to fit in the ECDSA
	// signature.
	b, err := contextualizedSHA256(ch, data, context, sha256.Size)
	if err != nil {
		return nil, err
	}

	R, S, err := ecdsa.Sign(rand.Reader, s.ec, b)
	if err != nil {
		return nil, err
	}

	m, err := asn1.Marshal(ecdsaSignature{R, S})
	if err != nil {
		return nil, err
	}

	sd := &SignedData{
		Header:    ch,
		Signature: m,
	}

	return proto.Marshal(sd)
}

// GetVerifier returns a Verifier from Signer.
func (s *Signer) GetVerifier() *Verifier {
	return &Verifier{&s.ec.PublicKey}
}

// Verify checks an ECDSA signature over the contextualized data, using the
// public key of the verifier.
func (v *Verifier) Verify(data []byte, context string, sig []byte) (bool, error) {
	// Deserialize the data and extract the CryptoHeader.
	var sd SignedData
	if err := proto.Unmarshal(sig, &sd); err != nil {
		return false, err
	}

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

	return ecdsa.Verify(v.ec, b, ecSig.R, ecSig.S), nil
}

// ToPrincipal produces a "key" type Prin for this verifier. This contains a
// serialized CryptoKey for this key.
func (v *Verifier) ToPrincipal() auth.Prin {
	ck := MarshalVerifierProto(v)

	// proto.Marshal won't fail here since we fill all required fields of the
	// message. Propagating impossible errors just leads to clutter later.
	data, _ := proto.Marshal(ck)

	return auth.NewKeyPrin(data)
}

// FromPrincipal deserializes a Verifier from a Prin.
func FromPrincipal(prin auth.Prin) (*Verifier, error) {
	if prin.Type != "key" {
		return nil, newError("invalid key principal")
	}
	var b auth.Bytes
	if ptr, ok := prin.Key.(*auth.Bytes); ok {
		b = *ptr
	} else if val, ok := prin.Key.(auth.Bytes); ok {
		b = val
	} else {
		return nil, newError("invalid key material")
	}

	var ck CryptoKey
	if err := proto.Unmarshal(b, &ck); err != nil {
		return nil, err
	}

	if *ck.Version != CryptoVersion_CRYPTO_VERSION_1 {
		return nil, newError("bad version")
	}

	if *ck.Purpose != CryptoKey_VERIFYING {
		return nil, newError("bad purpose")
	}

	if *ck.Algorithm != CryptoKey_ECDSA_SHA {
		return nil, newError("bad algorithm")
	}

	var ecvk ECDSA_SHA_VerifyingKeyV1
	if err := proto.Unmarshal(ck.Key, &ecvk); err != nil {
		return nil, err
	}

	ec, err := unmarshalECDSA_SHA_VerifyingKeyV1(&ecvk)
	if err != nil {
		return nil, err
	}

	return &Verifier{ec}, nil
}

// FromX509 creates a Verifier from an X509 certificate.
func FromX509(cert *x509.Certificate) (*Verifier, error) {
	ecpk, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, newError("invalid key type in certificate: must be ECDSA")
	}

	return &Verifier{ecpk}, nil
}

// CompareKey checks to see if the public key in the X.509 certificate matches
// the public key in the verifier.
func (v *Verifier) Equals(cert *x509.Certificate) bool {
	v2, err := FromX509(cert)
	if err != nil {
		return false
	}

	p := v.ToPrincipal()
	p2 := v2.ToPrincipal()
	return p.Identical(p2)
}

// UnmarshalVerifierProto decodes a verifying key from a CryptoKey protobuf
// message.
func UnmarshalVerifierProto(ck *CryptoKey) (*Verifier, error) {
	if *ck.Version != CryptoVersion_CRYPTO_VERSION_1 {
		return nil, newError("bad version")
	}

	if *ck.Purpose != CryptoKey_VERIFYING {
		return nil, newError("bad purpose")
	}

	if *ck.Algorithm != CryptoKey_ECDSA_SHA {
		return nil, newError("bad algorithm")
	}

	k := new(ECDSA_SHA_VerifyingKeyV1)
	if err := proto.Unmarshal(ck.Key, k); err != nil {
		return nil, err
	}

	if *k.Curve != NamedEllipticCurve_PRIME256_V1 {
		return nil, newError("bad curve")
	}

	s := new(Verifier)
	s.ec = new(ecdsa.PublicKey)
	s.ec.Curve = elliptic.P256()
	s.ec.X, s.ec.Y = elliptic.Unmarshal(elliptic.P256(), k.EcPublic)
	return s, nil
}

// CreateHeader instantiates and fills in a header for this verifying key.
func (v *Verifier) CreateHeader() (*CryptoHeader, error) {
	k := marshalECDSA_SHA_VerifyingKeyV1(v.ec)
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

// contextualizeData produces a single string from a header, data, and a context.
func contextualizeData(h *CryptoHeader, data []byte, context string) ([]byte, error) {
	s := &SignaturePDU{
		Header:  h,
		Context: proto.String(context),
		Data:    data,
	}

	return proto.Marshal(s)
}

// contextualizedSHA256 performs a SHA-256 sum over contextualized data.
func contextualizedSHA256(h *CryptoHeader, data []byte, context string, digestLen int) ([]byte, error) {
	b, err := contextualizeData(h, data, context)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(b)
	return hash[:digestLen], nil
}

// GenerateCrypter instantiates a new Crypter with fresh keys.
func GenerateCrypter() (*Crypter, error) {
	c := &Crypter{
		aesKey:  make([]byte, aesKeySize),
		hmacKey: make([]byte, hmacKeySize),
	}

	if _, err := rand.Read(c.aesKey); err != nil {
		return nil, err
	}

	if _, err := rand.Read(c.hmacKey); err != nil {
		return nil, err
	}

	return c, nil
}

// Encrypt encrypts plaintext into ciphertext and protects ciphertext integrity
// with a MAC.
func (c *Crypter) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.aesKey)
	if err != nil {
		return nil, err
	}

	ch, err := c.CreateHeader()
	if err != nil {
		return nil, err
	}

	// A ciphertext consists of an IV, encrypted bytes, and the output of
	// HMAC-SHA256.
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	s := cipher.NewCTR(block, iv)
	s.XORKeyStream(ciphertext[aes.BlockSize:], data)

	mac := hmac.New(sha256.New, c.hmacKey)
	m := mac.Sum(ciphertext)

	ed := &EncryptedData{
		Header:     ch,
		Iv:         iv,
		Ciphertext: ciphertext[aes.BlockSize:],
		Mac:        m,
	}

	return proto.Marshal(ed)
}

// Decrypt checks the MAC then decrypts ciphertext into plaintext.
func (c *Crypter) Decrypt(ciphertext []byte) ([]byte, error) {
	var ed EncryptedData
	if err := proto.Unmarshal(ciphertext, &ed); err != nil {
		return nil, err
	}

	// TODO(tmroeder): we're currently mostly ignoring the CryptoHeader,
	// since we only have one key.
	if *ed.Header.Version != CryptoVersion_CRYPTO_VERSION_1 {
		return nil, newError("bad version")
	}

	// Check the HMAC before touching the ciphertext.
	fullCiphertext := make([]byte, len(ed.Iv)+len(ed.Ciphertext))
	copy(fullCiphertext, ed.Iv)
	copy(fullCiphertext[len(ed.Iv):], ed.Ciphertext)

	mac := hmac.New(sha256.New, c.hmacKey)
	m := mac.Sum(fullCiphertext)
	if !hmac.Equal(m, ed.Mac) {
		return nil, newError("bad HMAC")
	}

	block, err := aes.NewCipher(c.aesKey)
	if err != nil {
		return nil, err
	}

	s := cipher.NewCTR(block, ed.Iv)
	data := make([]byte, len(ed.Ciphertext))
	s.XORKeyStream(data, ed.Ciphertext)
	return data, nil
}

// marshalAES_CTR_HMAC_SHA_CryptingKeyV1 encodes a private AES/HMAC key pair
// into a protobuf message.
func marshalAES_CTR_HMAC_SHA_CryptingKeyV1(c *Crypter) *AES_CTR_HMAC_SHA_CryptingKeyV1 {
	return &AES_CTR_HMAC_SHA_CryptingKeyV1{
		Mode:        CryptoCipherMode_CIPHER_MODE_CTR.Enum(),
		AesPrivate:  c.aesKey,
		HmacPrivate: c.hmacKey,
	}
}

// MarshalCrypterProto encodes a Crypter as a CryptoKey protobuf message.
func MarshalCrypterProto(c *Crypter) (*CryptoKey, error) {
	k := marshalAES_CTR_HMAC_SHA_CryptingKeyV1(c)

	// Note that we don't need to call zeroBytes on k.AesPrivate or
	// k.HmacPrivate, since they're just slice references to the underlying
	// keys.
	m, err := proto.Marshal(k)
	if err != nil {
		return nil, err
	}

	ck := &CryptoKey{
		Version:   CryptoVersion_CRYPTO_VERSION_1.Enum(),
		Purpose:   CryptoKey_CRYPTING.Enum(),
		Algorithm: CryptoKey_AES_CTR_HMAC_SHA.Enum(),
		Key:       m,
	}

	return ck, nil
}

// UnmarshalCrypterProto decodes a crypting key from a CryptoKey protobuf
// message.
func UnmarshalCrypterProto(ck *CryptoKey) (*Crypter, error) {
	if *ck.Version != CryptoVersion_CRYPTO_VERSION_1 {
		return nil, newError("bad version")
	}

	if *ck.Purpose != CryptoKey_CRYPTING {
		return nil, newError("bad purpose")
	}

	if *ck.Algorithm != CryptoKey_AES_CTR_HMAC_SHA {
		return nil, newError("bad algorithm")
	}

	var k AES_CTR_HMAC_SHA_CryptingKeyV1
	if err := proto.Unmarshal(ck.Key, &k); err != nil {
		return nil, err
	}

	if *k.Mode != CryptoCipherMode_CIPHER_MODE_CTR {
		return nil, newError("bad cipher mode")
	}

	c := new(Crypter)
	c.aesKey = k.AesPrivate
	c.hmacKey = k.HmacPrivate
	return c, nil
}

// CreateHeader instantiates and fills in a header for this crypting key.
func (c *Crypter) CreateHeader() (*CryptoHeader, error) {
	k := marshalAES_CTR_HMAC_SHA_CryptingKeyV1(c)
	b, err := proto.Marshal(k)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(b)

	h := sha1.Sum(b)
	ch := &CryptoHeader{
		Version: CryptoVersion_CRYPTO_VERSION_1.Enum(),
		KeyHint: h[:4],
	}

	return ch, nil

}

// GenerateDeriver generates a deriver with a fresh secret.
func GenerateDeriver() (*Deriver, error) {
	d := new(Deriver)
	d.secret = make([]byte, deriverSecretSize)
	if _, err := rand.Read(d.secret); err != nil {
		return nil, err
	}

	return d, nil
}

// Derive uses HKDF with HMAC-SHA256 to derive key bytes in its material
// parameter.
func (d *Deriver) Derive(salt, context, material []byte) error {
	f := hkdf.New(sha256.New, d.secret, salt, context)
	if _, err := f.Read(material); err != nil {
		return err
	}

	return nil
}

// marshalHMAC_SHA_DerivingKeyV1 encodes a deriving key as a protobuf message.
func marshalHMAC_SHA_DerivingKeyV1(d *Deriver) *HMAC_SHA_DerivingKeyV1 {
	return &HMAC_SHA_DerivingKeyV1{
		Mode:        CryptoDerivingMode_DERIVING_MODE_HKDF.Enum(),
		HmacPrivate: d.secret,
	}
}

// MarshalDeriverProto encodes a Deriver as a CryptoKey protobuf message.
func MarshalDeriverProto(d *Deriver) (*CryptoKey, error) {
	k := marshalHMAC_SHA_DerivingKeyV1(d)

	// Note that we don't need to call zeroBytes on k.HmacPrivate since
	// it's just a slice reference to the underlying keys.
	m, err := proto.Marshal(k)
	if err != nil {
		return nil, err
	}

	ck := &CryptoKey{
		Version:   CryptoVersion_CRYPTO_VERSION_1.Enum(),
		Purpose:   CryptoKey_DERIVING.Enum(),
		Algorithm: CryptoKey_HMAC_SHA.Enum(),
		Key:       m,
	}

	return ck, nil
}

// UnmarshalDeriverProto decodes a deriving key from a CryptoKey protobuf
// message.
func UnmarshalDeriverProto(ck *CryptoKey) (*Deriver, error) {
	if *ck.Version != CryptoVersion_CRYPTO_VERSION_1 {
		return nil, newError("bad version")
	}

	if *ck.Purpose != CryptoKey_DERIVING {
		return nil, newError("bad purpose")
	}

	if *ck.Algorithm != CryptoKey_HMAC_SHA {
		return nil, newError("bad algorithm")
	}

	var k HMAC_SHA_DerivingKeyV1
	if err := proto.Unmarshal(ck.Key, &k); err != nil {
		return nil, err
	}

	if *k.Mode != CryptoDerivingMode_DERIVING_MODE_HKDF {
		return nil, newError("bad deriving mode")
	}

	d := new(Deriver)
	d.secret = k.HmacPrivate
	return d, nil
}

// A Keys manages a set of signing, verifying, encrypting, and key-deriving
// keys.
type Keys struct {
	dir      string
	policy   string
	keyTypes KeyType

	SigningKey   *Signer
	CryptingKey  *Crypter
	VerifyingKey *Verifier
	DerivingKey  *Deriver
	Delegation   *Attestation
	Cert         *x509.Certificate
}

// X509Path returns the path to the verifier key, stored as an X.509
// certificate.
func (k *Keys) X509Path() string {
	if k.dir == "" {
		return ""
	}

	return path.Join(k.dir, "cert")
}

// PBEKeysetPath returns the path for stored keys.
func (k *Keys) PBEKeysetPath() string {
	if k.dir == "" {
		return ""
	}
	return path.Join(k.dir, "keys")
}

// PBESignerPath returns the path for a stored signing key.
func (k *Keys) PBESignerPath() string {
	if k.dir == "" {
		return ""
	}
	return path.Join(k.dir, "signer")
}

// SealedKeysetPath returns the path for a stored signing key.
func (k *Keys) SealedKeysetPath() string {
	if k.dir == "" {
		return ""
	}

	return path.Join(k.dir, "sealed_keyset")
}

// DelegationPath returns the path for a stored delegation.
func (k *Keys) DelegationPath() string {
	if k.dir == "" {
		return ""
	}

	return path.Join(k.dir, "delegation")
}

// zeroBytes clears the bytes in a slice.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// NewTemporaryKeys creates a new Keys structure with the specified keys.
func NewTemporaryKeys(keyTypes KeyType) (*Keys, error) {
	k := &Keys{
		keyTypes: keyTypes,
	}
	if k.keyTypes == 0 || (k.keyTypes & ^Signing & ^Crypting & ^Deriving != 0) {
		return nil, newError("bad key type")
	}

	var err error
	if k.keyTypes&Signing == Signing {
		k.SigningKey, err = GenerateSigner()
		if err != nil {
			return nil, err
		}

		k.VerifyingKey = k.SigningKey.GetVerifier()
	}

	if k.keyTypes&Crypting == Crypting {
		k.CryptingKey, err = GenerateCrypter()
		if err != nil {
			return nil, err
		}
	}

	if k.keyTypes&Deriving == Deriving {
		k.DerivingKey, err = GenerateDeriver()
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
		return nil, newError("must supply a signer and a name")
	}

	if signer.Cert == nil || signer.SigningKey == nil {
		return nil, newError("the signing key must have a SigningKey and a Cert")
	}

	if keyTypes & ^Signing != 0 {
		return nil, newError("can't sign a key that has no signer")
	}

	k, err := NewOnDiskPBEKeys(keyTypes, password, path, nil)
	if err != nil {
		return nil, err
	}

	// If there's already a cert, then this means that there was already a
	// keyset on disk, so don't create a new signed certificate.
	if k.Cert == nil {
		k.Cert, err = signer.SigningKey.CreateSignedX509(signer.Cert, serial, k.VerifyingKey, name)
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
		// There are two different types of keysets: in one there's
		// just a Signer, so we use an encrypted PEM format. In the
		// other, there are multiple keys, so we use a custom protobuf
		// format.
		if k.keyTypes & ^Signing != 0 {
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
				defer zeroBytes(data)

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
				defer zeroBytes(m)

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
		} else {
			// There's just a signer, so do PEM encryption of the encoded key.
			f, err := os.Open(k.PBESignerPath())
			if err == nil {
				defer f.Close()
				// Read the signer.
				ss, err := ioutil.ReadAll(f)
				if err != nil {
					return nil, err
				}

				pb, rest := pem.Decode(ss)
				if pb == nil || len(rest) > 0 {
					return nil, newError("decoding failure")
				}

				p, err := x509.DecryptPEMBlock(pb, password)
				if err != nil {
					return nil, err
				}
				defer zeroBytes(p)

				err = k.loadCert()
				if err != nil {
					return nil, err
				}

				if k.SigningKey, err = UnmarshalSignerDER(p); err != nil {
					return nil, err
				}
				k.VerifyingKey = k.SigningKey.GetVerifier()
			} else {
				// Create a fresh key and store it to the PBESignerPath.
				if k.SigningKey, err = GenerateSigner(); err != nil {
					return nil, err
				}

				k.VerifyingKey = k.SigningKey.GetVerifier()
				p, err := MarshalSignerDER(k.SigningKey)
				if err != nil {
					return nil, err
				}
				defer zeroBytes(p)

				pb, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", p, password, x509.PEMCipherAES128)
				if err != nil {
					return nil, err
				}

				pbes, err := util.CreatePath(k.PBESignerPath(), 0700, 0600)
				if err != nil {
					return nil, err
				}
				defer pbes.Close()

				if err = pem.Encode(pbes, pb); err != nil {
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
	}

	return k, nil
}

func (k *Keys) newCert(name *pkix.Name) (err error) {
	k.Cert, err = k.SigningKey.CreateSelfSignedX509(name)
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
	self, err := t.GetTaoName()
	if err != nil {
		return nil, err
	}

	if k.SigningKey != nil {
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

	pbed := &PBEData{
		Version: CryptoVersion_CRYPTO_VERSION_1.Enum(),
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
	defer zeroBytes(aesKey)

	// 64-byte HMAC-SHA256 key.
	hmacKey := pbkdf2.Key(password, pbed.Salt[8:], int(*pbed.Iterations), 64, sha256.New)
	defer zeroBytes(hmacKey)
	c := &Crypter{aesKey, hmacKey}

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
	if *pbed.Version != CryptoVersion_CRYPTO_VERSION_1 {
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
	defer zeroBytes(aesKey)

	// 64-byte HMAC-SHA256 key.
	hmacKey := pbkdf2.Key(password, pbed.Salt[8:], int(*pbed.Iterations), 64, sha256.New)
	defer zeroBytes(hmacKey)
	c := &Crypter{aesKey, hmacKey}

	// Note that we're abusing the PBEData format here, since the IV and
	// the MAC are actually contained in the ciphertext from Encrypt().
	data, err := c.Decrypt(pbed.Ciphertext)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// MarshalKeyset encodes the keys into a protobuf message.
func MarshalKeyset(k *Keys) (*CryptoKeyset, error) {
	var cks []*CryptoKey
	if k.keyTypes&Signing == Signing {
		ck, err := MarshalSignerProto(k.SigningKey)
		if err != nil {
			return nil, err
		}

		cks = append(cks, ck)
	}

	if k.keyTypes&Crypting == Crypting {
		ck, err := MarshalCrypterProto(k.CryptingKey)
		if err != nil {
			return nil, err
		}

		cks = append(cks, ck)
	}

	if k.keyTypes&Deriving == Deriving {
		ck, err := MarshalDeriverProto(k.DerivingKey)
		if err != nil {
			return nil, err
		}

		cks = append(cks, ck)
	}

	ckset := &CryptoKeyset{
		Keys: cks,
	}

	return ckset, nil
}

// UnmarshalKeyset decodes a CryptoKeyset into a temporary Keys structure. Note
// that this Keys structure doesn't have any of its variables set.
func UnmarshalKeyset(cks *CryptoKeyset) (*Keys, error) {
	k := new(Keys)
	var err error
	for i := range cks.Keys {
		if *cks.Keys[i].Purpose == CryptoKey_SIGNING {
			if k.SigningKey, err = UnmarshalSignerProto(cks.Keys[i]); err != nil {
				return nil, err
			}

			k.VerifyingKey = k.SigningKey.GetVerifier()
		}

		if *cks.Keys[i].Purpose == CryptoKey_CRYPTING {
			if k.CryptingKey, err = UnmarshalCrypterProto(cks.Keys[i]); err != nil {
				return nil, err
			}
		}

		if *cks.Keys[i].Purpose == CryptoKey_DERIVING {
			if k.DerivingKey, err = UnmarshalDeriverProto(cks.Keys[i]); err != nil {
				return nil, err
			}
		}
	}

	return k, nil
}

// NewOnDiskTaoSealedKeys sets up the keys sealed under a host Tao or reads sealed keys.
func NewOnDiskTaoSealedKeys(keyTypes KeyType, t Tao, path, policy string) (*Keys, error) {
	k := &Keys{
		keyTypes: keyTypes,
		dir:      path,
		policy:   policy,
	}

	// Check to see if there are already keys.
	f, err := os.Open(k.SealedKeysetPath())
	if err == nil {
		defer f.Close()
		ks, err := ioutil.ReadAll(f)
		if err != nil {
			return nil, err
		}

		data, p, err := t.Unseal(ks)
		if err != nil {
			return nil, err
		}
		defer zeroBytes(data)

		if p != policy {
			return nil, newError("invalid policy from Unseal")
		}

		var cks CryptoKeyset
		if err = proto.Unmarshal(data, &cks); err != nil {
			return nil, err
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
		if k.SigningKey != nil {
			ds, err := ioutil.ReadFile(k.DelegationPath())
			if err != nil {
				return nil, err
			}

			k.Delegation = new(Attestation)
			if err := proto.Unmarshal(ds, k.Delegation); err != nil {
				return nil, err
			}
		}
	} else {
		// Create and store a new set of keys.
		k, err = NewTemporaryKeys(keyTypes)
		if err != nil {
			return nil, err
		}

		k.dir = path
		k.policy = policy

		cks, err := MarshalKeyset(k)
		if err != nil {
			return nil, err
		}

		// TODO(tmroeder): defer zeroKeyset(cks)

		m, err := proto.Marshal(cks)
		if err != nil {
			return nil, err
		}
		defer zeroBytes(m)

		enc, err := t.Seal(m, policy)
		if err != nil {
			return nil, err
		}

		if err = util.WritePath(k.SealedKeysetPath(), enc, 0700, 0600); err != nil {
			return nil, err
		}

		// Get and write a delegation.
		if k.SigningKey != nil {
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

			m, err := proto.Marshal(k.Delegation)
			if err != nil {
				return nil, err
			}

			if err = util.WritePath(k.DelegationPath(), m, 0700, 0600); err != nil {
				return nil, err
			}
		}
	}

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
		zeroBytes(dec)
		return nil, newError("The decrypted value had length %d, but it should have had length %d", len(dec), length)
	}

	return dec, nil
}
