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
	"crypto/x509"
	"crypto/x509/pkix"
	// "encoding/asn1"
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
	p := rsaKey.Primes[0]
	if p == nil {
		return keyComponents, nil
	}
	q := rsaKey.Primes[1]
	if q == nil {
		return keyComponents, nil
	}
	return keyComponents, nil
}

func DeserializeRsaPrivateComponents(keyComponents [][]byte, rsaKey *rsa.PrivateKey) (error) {
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
	rsaKey.Primes = append(rsaKey.Primes, p)
	rsaKey.Primes = append(rsaKey.Primes, q)
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

func DeserializeRsaPublicComponents(rsaKey *rsa.PublicKey, keyComponents [][]byte) (error) {
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

func GenerateCryptoKey(keyType string, keyName *string, keyEpoch *int32, keyPurpose *string, keyStatus *string) *CryptoKey {
	cryptoKey := new(CryptoKey)
	switch keyType {
	case "aes-128-raw":
		keyBuf, err := randBytes(16)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyBuf)
	case "aes-256-raw":
		keyBuf, err := randBytes(32)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyBuf)
	case "aes-128-ctr":
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
	case "aes-256-ctr":
		keyBuf, err := randBytes(32)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyBuf)
		ivBuf, err := randBytes(32)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, ivBuf)
	case "aes-128-sha-256-cbc":
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
	case "aes-256-sha-384-cbc":
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
	case "sha-256-hmac":
		keyBuf, err := randBytes(32)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyBuf)
	case "sha-384-hmac":
		keyBuf, err := randBytes(48)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyBuf)
	case "sha-512-hmac":
		keyBuf, err := randBytes(64)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyBuf)
	case "rsa-1024":
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
	case "rsa-2048":
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
	case "rsa-3072":
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
	case "ecdsa-P256":
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil
		}
		keyComponent, err := SerializeEcdsaPrivateComponents(ecKey)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyComponent)
	case "ecdsa-P384":
		ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil
		}
		keyComponent, err := SerializeEcdsaPrivateComponents(ecKey)
		if err != nil {
			return nil
		}
		cryptoKey.KeyComponents = append(cryptoKey.KeyComponents, keyComponent)
	default:
		return nil
	}
	ver := CryptoVersion_CRYPTO_VERSION_2
	ch := &CryptoHeader {
		Version: &ver,
		KeyName: keyName,
		KeyEpoch: keyEpoch,
		KeyType: &keyType,
		KeyPurpose: keyPurpose,
		KeyStatus: keyStatus,
	}
	cryptoKey.KeyHeader = ch
	return cryptoKey
}

func MarshalCryptoKey(ck CryptoKey) []byte {
	// return proto.Marshal(ck)
	return nil
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
	key *CryptoKey

	privateKey *crypto.PrivateKey
}

// A Verifier is used to verify signatures.
type Verifier struct {
	key *CryptoKey

	publicKey *crypto.PublicKey
}

// A Crypter is used to encrypt and decrypt data.
type Crypter struct {
	key *CryptoKey

	encryptingKeyBytes  []byte
	hmacKeyBytes[]byte
}

// A Deriver is used to derive key material from a context using HKDF.
type Deriver struct {
	key *CryptoKey

	secret []byte
}

func SignerFromCryptoKey(key CryptoKey) *Signer {
	return nil
}

func VerifierFromCryptoKey(key CryptoKey) *Verifier {
	return nil
}

func CrypterFromCryptoKey(key CryptoKey) *Crypter {
	return nil
}

func DeriverFromCryptoKey(key CryptoKey) *Deriver {
	return nil
}

func (s *Signer) GetVerifierFromSigner() *Verifier {
	// return &Verifier{&s.ec.PublicKey}
	return nil
}

func (s *Signer) GetSignerPrivateKey() *crypto.PrivateKey {
	// return &s.PrivateKey
	return nil
}

func (s *Verifier) GetVerifierPublicKey() *crypto.PublicKey {
	// switch(v.key.KeyType) {
	// default:
	// }
	// return s.ec
	return nil
}

func (v *Verifier) CanonicalKeyBytesFromVerifier() []byte {
	// switch(v.key.KeyType) {
	// default:
	// }
	return nil
}

func (s *Signer) CanonicalKeyBytesFromSigner() []byte {
	// return x509.MarshalECPublicKey(s.ec)
	return nil
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
	if s.key.KeyHeader.KeyType == nil {
		return nil, errors.New("No key type")
	}
	var publicKey interface{}
	switch(*s.key.KeyHeader.KeyType) {
	case "rsa-1024", "rsa-2048", "rsa-3072":
		priv := (*s.privateKey).(rsa.PrivateKey)
		publicKey = priv.PublicKey
	case "ecdsa-P256", "ecdsa-P384":
		priv := (*s.privateKey).(ecdsa.PrivateKey)
		publicKey = priv.PublicKey
	default:
		return nil, errors.New("Unsupported key type")
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, s.privateKey)
	if err != nil {
		return nil, err
	}
	return der, nil
}

// CreateSelfSignedX509 creates a self-signed X.509 certificate for the public
// key of this Signer.
func (s *Signer) CreateSelfSignedX509(pkAlg int, sigAlg int, sn int64,name *pkix.Name) (*x509.Certificate, error) {
	template := PrepareX509Template(pkAlg, sigAlg, sn, name)
	template.IsCA = true
	template.BasicConstraintsValid = true
	template.Issuer = template.Subject

	if s.key.KeyHeader.KeyType == nil {
		return nil, errors.New("No key type")
	}
	var pub interface{}
	switch(*s.key.KeyHeader.KeyType) {
	case "rsa-1024", "rsa-2048", "rsa-3072":
		priv := (*s.privateKey).(rsa.PrivateKey)
		pub = priv.PublicKey
	case "ecdsa-P256", "ecdsa-P384":
		priv := (*s.privateKey).(ecdsa.PrivateKey)
		pub = priv.PublicKey
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

// Sign computes a sigature over the contextualized data, using the
// private key of the signer.
func (s *Signer) Sign(data []byte, context string) ([]byte, error) {
	ch, err := s.CreateHeader()
	if err != nil {
		return nil, err
	}

	// TODO(tmroeder): for compatibility with the C++ version, we should
	// compute ECDSA signatures over hashes truncated to fit in the ECDSA
	// signature.
	// FIX
	// b, err := contextualizedSHA256(ch, data, context, sha256.Size)
	// if err != nil {
		// return nil, err
	// }

	// FIX R, S, err := ecdsa.Sign(rand.Reader, s.ec, b)
	// R, S, err := ecdsa.Sign(rand.Reader, nil, b)
	// if err != nil {
		// return nil, err
	// }

	// FIX m, err := asn1.Marshal(ecdsaSignature{R, S})
	var m []byte
	if err != nil {
		return nil, err
	}

	sd := &SignedData{
		Header:    ch,
		Signature: m,
	}

	return proto.Marshal(sd)
}

// Verify checks a signature over the contextualized data, using the
// public key of the verifier.
func (v *Verifier) Verify(data []byte, context string, sig []byte) (bool, error) {
/*
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
 */
	// FIX
	return true, nil
}

// MarshalKey serializes a Verifier.
func (v *Verifier) MarshalKey() []byte {
	// FIX
	var data []byte
	//ck := MarshalVerifierProto(v)

	// proto.Marshal won't fail here since we fill all required fields of the
	// message. Propagating impossible errors just leads to clutter later.
	//data, _ := proto.Marshal(ck)

	return data
}

// UnmarshalKey deserializes a Verifier.
func UnmarshalKey(material []byte) (*Verifier, error) {
/*
	var ck CryptoKey
	if err := proto.Unmarshal(material, &ck); err != nil {
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

	ec, err := unmarshalECDSASHAVerifyingKeyV1(&ecvk)
	if err != nil {
		return nil, err
	}

	return &Verifier{ec}, nil
 */
	// FIX
	return nil, nil
}

// SignsForPrincipal returns true when prin is (or is a subprincipal of) this verifier key.
func (v *Verifier) SignsForPrincipal(prin auth.Prin) bool {
	return auth.SubprinOrIdentical(prin, v.ToPrincipal())
}

// FromX509 creates a Verifier from an X509 certificate.
func FromX509(cert *x509.Certificate) (*Verifier, error) {
	// ecpk, ok := cert.PublicKey.(*ecdsa.PublicKey)
	// if !ok {
		// return nil, errors.New("invalid key type in certificate: must be ECDSA")
	// }

	// FIX: return &Verifier{ecpk}, nil
	return nil, nil
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

// UnmarshalVerifierProto decodes a verifying key from a CryptoKey protobuf
// message.
func UnmarshalVerifierProto(ck *CryptoKey) (*Verifier, error) {
	// FIX return s, nil
	return nil, nil
}

// CreateHeader fills in a header for this verifying key.
func (v *Verifier) CreateHeaderFromVerifier() (*CryptoHeader, error) {
	// FIX return ch, nil
	return nil, nil
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

// Encrypt encrypts plaintext into ciphertext and protects ciphertext integrity
// with a MAC.
func (c *Crypter) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.encryptingKeyBytes)
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

	mac := hmac.New(sha256.New, c.hmacKeyBytes)
	mac.Write(ciphertext)
	m := mac.Sum(nil)

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
		return nil, errors.New("bad version")
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
	data := make([]byte, len(ed.Ciphertext))
	s.XORKeyStream(data, ed.Ciphertext)
	return data, nil
}

func (c *Signer) CreateHeader() (*CryptoHeader, error) {
	return nil, nil
}

// CreateHeader instantiates and fills in a header for this crypting key.
func (c *Crypter) CreateHeader() (*CryptoHeader, error) {
	// FIX k := marshalAESCTRHMACSHACryptingKeyV1(c)
	//b, err := proto.Marshal(k)
	//if err != nil {
		//return nil, err
	//}
	var b []byte
	defer ZeroBytes(b)

	// h := sha1.Sum(b)
	ch := &CryptoHeader{
		Version: CryptoVersion_CRYPTO_VERSION_1.Enum(),
		// KeyHint: h[:4],
	}

	return ch, nil

}
