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
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	// "crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"errors"
	"math/big"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"

	// "golang.org/x/crypto/hkdf"
	// "golang.org/x/crypto/pbkdf2"
	"github.com/golang/crypto/hkdf"
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
	// mod, e, d, p, q
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

func PrivateKeyFromCryptoKey(k CryptoKey) (crypto.PrivateKey, error) {
	switch *k.KeyHeader.KeyType {
	case "rsa1024", "rsa2048", "rsa3072":
		rsaKey := new(rsa.PrivateKey)
		err := DeserializeRsaPrivateComponents(k.KeyComponents, rsaKey)
		if err != nil {
			return nil, errors.New("Can't DeserializeRsaPrivateComponents")
		}
		return crypto.PrivateKey(rsaKey), nil
	case "ecdsap256", "ecdsap384":
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
	switch *k.KeyHeader.KeyType {
	case "rsa1024-public":
	case "rsa2048-public":
	case "rsa3072-public":
		rsaKey := new(rsa.PublicKey)
		err := DeserializeRsaPublicComponents(rsaKey, k.KeyComponents)
		if err != nil {
			return nil, errors.New("Can't DeserializeRsaPublicComponents")
		}
		publicKey = crypto.PublicKey(rsaKey)
	case "ecdsap256-public":
	case "ecdsap384-public":
		ecKey, err := DeserializeEcdsaPublicComponents(k.KeyComponents[0])
		if err != nil {
			return nil, errors.New("Can't DeserializeEcdsaPublicComponents")
		}
		publicKey = crypto.PublicKey(ecKey)
	default:
		return nil, errors.New("Unsupported key type")
	}
	return publicKey, errors.New("Unsupported key type")
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
	case "aes256-ctr-hmacsha256":
		keyBuf, err := randBytes(32)
		if err != nil {
			return nil
		}
		hmacBuf, err := randBytes(32)
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
	case "aes128-cbc-hmacsha256":
		keyBuf, err := randBytes(16)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyBuf)
		ivBuf, err := randBytes(32)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, ivBuf)
	case "aes256-cbc-hmacsha384":
		keyBuf, err := randBytes(32)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyBuf)
		ivBuf, err := randBytes(48)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, ivBuf)
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

// A Signer is used to sign and verify signatures
type Signer struct {
	header *CryptoHeader

	privateKey crypto.PrivateKey
}

// A Verifier is used to verify signatures.
type Verifier struct {
	header *CryptoHeader

	publicKey crypto.PublicKey
}

// A Crypter is used to encrypt and decrypt data.
type Crypter struct {
	header *CryptoHeader

	encryptingKeyBytes []byte
	hmacKeyBytes       []byte
}

// A Deriver is used to derive key material from a context using HKDF.
type Deriver struct {
	header *CryptoHeader

	secret []byte
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
		header:     k.KeyHeader,
		privateKey: privateKey,
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
		header:    k.KeyHeader,
		publicKey: publicKey,
	}
	return v
}

func CrypterFromCryptoKey(k CryptoKey) *Crypter {
	c := &Crypter{
		header: k.KeyHeader,
	}
	switch *k.KeyHeader.KeyType {
	case "aes128-ctr", "aes256-ctr":
		c.encryptingKeyBytes = k.KeyComponents[0]
	case "aes128-gcm", "aes256-gcm",
		"aes128-ctr-hmacsha256", "aes256-ctr-hmacsha256", "aes256-ctr-hmacsha512",
		"aes128-cbc-hmacsha256", "aes256-cbc-hmacsha384":
		c.encryptingKeyBytes = k.KeyComponents[0]
		c.hmacKeyBytes = k.KeyComponents[1]
	case "hmacsha256", "hmacsha384", "hmacsha512":
		c.hmacKeyBytes = k.KeyComponents[1]
	default:
		return nil
	}
	return c
}

func DeriverFromCryptoKey(k CryptoKey) *Deriver {
	d := &Deriver{
		header: k.KeyHeader,
		secret: k.KeyComponents[0],
	}
	return d
}

func (s *Signer) GetVerifierFromSigner() *Verifier {
	var pub crypto.PublicKey
	switch *s.header.KeyType {
	case "rsa1024", "rsa2048", "rsa3072":
		pub = &(s.privateKey).(*rsa.PrivateKey).PublicKey
	case "ecdsap256", "ecdsap384":
		pub = &(s.privateKey).(*ecdsa.PrivateKey).PublicKey
	default:
		return nil
	}
	newKeyType := *s.header.KeyType + "-public"
	var newHeader CryptoHeader
	newHeader.Version = s.header.Version
	newHeader.KeyName = s.header.KeyName
	newHeader.KeyEpoch = s.header.KeyEpoch
	newHeader.KeyType = &newKeyType
	newHeader.KeyPurpose = s.header.KeyPurpose
	newHeader.KeyStatus = s.header.KeyStatus
	v := &Verifier{
		header:    &newHeader,
		publicKey: pub,
	}
	return v
}

func (v *Verifier) GetVerifierPublicKey() crypto.PublicKey {
	return v.publicKey
}

func (s *Signer) GetSignerPrivateKey() crypto.PrivateKey {
	return s.privateKey
}

func (v *Verifier) CanonicalKeyBytesFromVerifier() ([]byte, error) {
	kr, err := x509.MarshalPKIXPublicKey(v.publicKey)
	if err != nil {
		return kr, err
	}
	// Now hash with type
	// Note: not sure this is needed since we now use MarshalPKIXPublic
	b := append([]byte(*v.header.KeyType), kr...)
	h := sha256.Sum256(b)
	return h[0:32], err
}

func (s *Signer) CanonicalKeyBytesFromSigner() ([]byte, error) {
	return s.GetVerifierFromSigner().CanonicalKeyBytesFromVerifier()
}

// ToPrincipal produces a "key" type Prin for this signer. This contains a
// serialized CryptoKey for the public portion of the signing key.
func (s *Signer) ToPrincipal() auth.Prin {
	var data []byte
	return auth.NewKeyPrin(data)
}

// ToPrincipal produces a "key" type Prin for this verifier. This contains a
// hash of a serialized CryptoKey for this key.
func (v *Verifier) ToPrincipal() auth.Prin {
	var data []byte
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
	if s.header.KeyType == nil {
		return nil, errors.New("No key type")
	}
	var pub interface{}
	switch *s.header.KeyType {
	case "rsa1024", "rsa2048", "rsa3072":
		pub = &(s.privateKey).(*rsa.PrivateKey).PublicKey
	case "ecdsap256", "ecdsap384":
		pub = &(s.privateKey).(*ecdsa.PrivateKey).PublicKey
	default:
		return nil, errors.New("Unsupported key type")
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, s.privateKey)
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

	if s.header.KeyType == nil {
		return nil, errors.New("No key type")
	}
	var pub interface{}
	switch *s.header.KeyType {
	case "rsa1024", "rsa2048", "rsa3072":
		pub = &(s.privateKey).(*rsa.PrivateKey).PublicKey
	case "ecdsap256", "ecdsap384":
		pub = &(s.privateKey).(*ecdsa.PrivateKey).PublicKey
	default:
		return nil, errors.New("Unsupported key type")
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, s.privateKey)
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
	return cert.CreateCRL(rand.Reader, s.privateKey, revokedCerts, now, expiry)
}

// CreateSignedX509 creates a signed X.509 certificate for some other subject's
// key.
func (s *Signer) CreateSignedX509(caCert *x509.Certificate, certSerial int, subjectKey *Verifier,
	pkAlg int, sigAlg int, sn int64, subjectName *pkix.Name) (*x509.Certificate, error) {
	template := PrepareX509Template(pkAlg, sigAlg, sn, subjectName)
	template.SerialNumber = new(big.Int).SetInt64(int64(certSerial))

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, subjectKey.publicKey, s.privateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
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

	newKeyType := *s.header.KeyType + "-public"
	newHeader := *s.header
	newHeader.KeyType = &newKeyType

	b, err := contextualizedSHA256(&newHeader, data, context, sha256.Size)
	if err != nil {
		return nil, err
	}

	// TODO(tmroeder): for compatibility with the C++ version, we should
	// compute ECDSA signatures over hashes truncated to fit in the ECDSA
	// signature.
	switch *s.header.KeyType {
	case "ecdsap256", "ecdsap384":
		R, S, err := ecdsa.Sign(rand.Reader, s.privateKey.(*ecdsa.PrivateKey), b)
		if err != nil {
			return nil, err
		}
		sig, err = asn1.Marshal(ecdsaSignature{R, S})
		if err != nil {
			return nil, err
		}
	case "rsa1024", "rsa2048", "rsa3072":
		// Use PKCS 1.5?
		sig, err = rsa.SignPKCS1v15(rand.Reader, s.privateKey.(*rsa.PrivateKey), crypto.SHA256, b)
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
	if *v.header.KeyType != *sd.Header.KeyType {
		return false, errors.New("Wrong signature algorithm")
	}

	switch *v.header.KeyType {
	case "ecdsap256-public", "ecdsap384-public":
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
		return ecdsa.Verify((v.publicKey).(*ecdsa.PublicKey), b, ecSig.R, ecSig.S), nil
	case "rsa1024-public", "rsa2048-public", "rsa3072-public":
		b, err := contextualizedSHA256(sd.Header, data, context, sha256.Size)
		if err != nil {
			return false, err
		}
		err = rsa.VerifyPKCS1v15((v.publicKey).(*rsa.PublicKey), crypto.SHA256, b, sd.Signature)
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
	var k CryptoKey
	k.KeyHeader = v.header
	keyComponent, err := SerializeEcdsaPublicComponents((v.publicKey).(*ecdsa.PublicKey))
	if err != nil {
	}
	k.KeyComponents = append(k.KeyComponents, keyComponent)
	return MarshalCryptoKey(k)
}

// UnmarshalKey deserializes a Verifier.
func UnmarshalKey(material []byte) (*Verifier, error) {
	var k CryptoKey
	err := proto.Unmarshal(material, &k)
	if err != nil {
		return nil, errors.New("Can't Unmarshal verifier")
	}
	// make sure its a verifying ecdsa key using sha
	if *k.KeyHeader.KeyPurpose != "verifying" {
		return nil, errors.New("Not a verifying key")
	}
	v := VerifierFromCryptoKey(k)
	if v == nil {
		return nil, errors.New("VerifierFromCryptoKey failed")
	}
	return v, nil
}

// SignsForPrincipal returns true when prin is (or is a subprincipal of) this verifier key.
func (v *Verifier) SignsForPrincipal(prin auth.Prin) bool {
	return auth.SubprinOrIdentical(prin, v.ToPrincipal())
}

// FromX509 creates a Verifier from an X509 certificate.
func FromX509(cert *x509.Certificate) (*Verifier, error) {
	var h CryptoHeader
	v := &Verifier{
		header:    &h,
		publicKey: cert.PublicKey,
	}
	return v, nil
}

// Equals checks to see if the public key in the X.509 certificate matches the
// public key in the verifier.
func (v *Verifier) KeyEqual(cert *x509.Certificate) bool {
	v2, err := FromX509(cert)
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
	block, err := aes.NewCipher(c.encryptingKeyBytes)
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

	mac := hmac.New(sha256.New, c.hmacKeyBytes)
	mac.Write(ciphertext)
	m := mac.Sum(nil)

	ed := &EncryptedData{
		Header:     c.header,
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
	if *ed.Header.KeyType != *c.header.KeyType {
		return nil, errors.New("bad key type")
	}

	// Check the HMAC before touching the ciphertext.
	fullCiphertext := make([]byte, len(ed.Iv)+len(ed.Ciphertext))
	copy(fullCiphertext, ed.Iv)
	copy(fullCiphertext[len(ed.Iv):], ed.Ciphertext)

	mac := hmac.New(sha256.New, c.hmacKeyBytes)
	mac.Write(fullCiphertext)
	m := mac.Sum(nil)
	if !hmac.Equal(m, ed.Mac) {
		return nil, errors.New("bad HMAC")
	}

	block, err := aes.NewCipher(c.encryptingKeyBytes)
	if err != nil {
		return nil, err
	}

	s := cipher.NewCTR(block, ed.Iv)
	plain := make([]byte, len(ed.Ciphertext))
	s.XORKeyStream(plain, ed.Ciphertext)
	return plain, nil
}

func (c *Crypter) encryptAes256ctrHmacsha512(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.encryptingKeyBytes)
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

	mac := hmac.New(sha512.New, c.hmacKeyBytes)
	mac.Write(ciphertext)
	m := mac.Sum(nil)

	ed := &EncryptedData{
		Header:     c.header,
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
	if *ed.Header.KeyType != "aes256-ctr-hmacsha512" {
		return nil, errors.New("bad key type")
	}

	// Check the HMAC before touching the ciphertext.
	fullCiphertext := make([]byte, len(ed.Iv)+len(ed.Ciphertext))
	copy(fullCiphertext, ed.Iv)
	copy(fullCiphertext[len(ed.Iv):], ed.Ciphertext)

	mac := hmac.New(sha512.New, c.hmacKeyBytes)
	mac.Write(fullCiphertext)
	m := mac.Sum(nil)
	if !hmac.Equal(m, ed.Mac) {
		return nil, errors.New("bad HMAC")
	}

	block, err := aes.NewCipher(c.encryptingKeyBytes)
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
	switch *c.header.KeyType {
	case "aes128-ctr-hmacsha256":
		return c.encryptAes128ctrHmacsha256(plain)
	case "aes256-ctr-hmacsha256":
		return c.encryptAes128ctrHmacsha256(plain)
	case "aes256-ctr-hmacsha512":
		return c.encryptAes256ctrHmacsha512(plain)
	default:
		return nil, errors.New("Unsupported crypting algorithm")
	}
}

// Decrypt checks the MAC then decrypts ciphertext into plaintext.
func (c *Crypter) Decrypt(ciphertext []byte) ([]byte, error) {
	switch *c.header.KeyType {
	case "aes128-ctr-hmacsha256":
		return c.decryptAes128ctrHmacsha256(ciphertext)
	case "aes256-ctr-hmacsha256":
		return c.decryptAes128ctrHmacsha256(ciphertext)
	case "aes256-ctr-hmacsha512":
		return c.decryptAes256ctrHmacsha512(ciphertext)
	default:
		return nil, errors.New("Unsupported crypting algorithm")
	}
}
