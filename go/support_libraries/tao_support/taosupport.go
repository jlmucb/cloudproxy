// Copyright (c) 2014, Google, Inc..  All rights reserved.
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
// File: taosupport.go

package tao_support

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"

	"github.com/golang/protobuf/proto"

	"github.com/jlmucb/cloudproxy/go/support_infrastructure/domain_service"
	"github.com/jlmucb/cloudproxy/go/support_libraries/domain_policy"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

// We should get this from the keySetType later.
const SizeofSymmetricKeys = 64

type TaoProgramData struct {
	// true after initialization.
	Initialized bool

	// Program name.
	TaoName string

	KeySetType string

	// DER encoded policy cert for domain.
	PolicyCert []byte

	// Private program key.
	ProgramKey tao.Keys

	// Symmetric Keys for program.
	ProgramSymKeys []byte

	// Program Cert.
	ProgramCert []byte

	// Cert Chain
	CertChain [][]byte

	// Path for program to read and write files.
	ProgramFilePath *string
}

// Support functions
func ZeroBytes(buf []byte) {
	n := len(buf)
	for i := 0; i < n; i++ {
		buf[i] = 0
	}
}

// This is not used now but Cloudproxy principals are in the Organization name.
func PrincipalNameFromDERCert(derCert []byte) *string {
	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		log.Printf("PrincipalNameFromDERCert: Can't get name from certificate\n")
		return nil
	}
	var name string
	if len(cert.Subject.Organization) > 0 && cert.Subject.Organization[0] != "" {
		name = cert.Subject.Organization[0]
	} else {
		name = cert.Subject.CommonName
	}
	return &name
}

func (pp *TaoProgramData) ClearTaoProgramData() {
	pp.Initialized = false
	pp.KeySetType = ""
	ZeroBytes([]byte(pp.TaoName))
	ZeroBytes(pp.PolicyCert)
	if pp.ProgramKey.SigningKey != nil {
		pp.ProgramKey.ClearKeys()
	}
	ZeroBytes(pp.ProgramSymKeys)
	ZeroBytes(pp.ProgramCert)
	pp.ProgramFilePath = nil
}

func (pp *TaoProgramData) FillTaoProgramData(keySetType string, policyCert []byte, taoName string,
	programKey tao.Keys, symKeys []byte, programCert []byte, certChain [][]byte,
	filePath *string) bool {
	pp.KeySetType = keySetType
	pp.PolicyCert = policyCert
	pp.TaoName = taoName
	pp.ProgramKey = programKey
	pp.ProgramSymKeys = symKeys
	pp.ProgramCert = programCert
	pp.CertChain = certChain
	pp.ProgramFilePath = filePath
	pp.Initialized = true
	return true
}

// RequestDomainServiceCert requests the signed Program Cert from SimpleDomainService
func RequestDomainServiceCert(network, addr string, requesting_key *tao.Keys,
	v *tao.Verifier) (*domain_policy.DomainCertResponse, error) {

	// Note requesting program key contains a self-signed cert to open channel.
	if requesting_key.Cert == nil {
		return nil, errors.New("RequestDomainServiceCert: Can't dial with an empty client certificate")
	}
	tlsCert, err := tao.EncodeTLSCert(requesting_key)
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

	var request domain_policy.DomainCertRequest
	request.Attestation, err = proto.Marshal(requesting_key.Delegation)
	signer := requesting_key.SigningKey.GetSigner()
	if signer == nil {
		return nil, err
	}
	key_type := "ECDSA"
	request.KeyType = &key_type
	request.SubjectPublicKey, err = domain_policy.GetPublicDerFromEcdsaKey(&signer.PublicKey)
	if err != nil {
		return nil, err
	}

	// Tao handshake: send client delegation.
	ms := util.NewMessageStream(conn)
	_, err = ms.WriteMessage(&request)
	if err != nil {
		return nil, err
	}

	// Read the new cert
	var response domain_policy.DomainCertResponse
	err = ms.ReadMessage(&response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

func InitializeSealedSymmetricKeys(filePath string, t tao.Tao, keysize int) (
	[]byte, error) {

	// Make up symmetric key and save sealed version.
	log.Printf("InitializeSealedSymmetricKeys\n")
	unsealed, err := tao.Parent().GetRandomBytes(keysize)
	if err != nil {
		return nil, errors.New("Can't get random bytes")
	}
	sealed, err := tao.Parent().Seal(unsealed, tao.SealPolicyDefault)
	if err != nil {
		return nil, errors.New("Can't seal random bytes")
	}
	ioutil.WriteFile(path.Join(filePath, "sealedsymmetricKey"), sealed, os.ModePerm)
	return unsealed, nil
}

// Returns key, cert and cert chain
func InitializeSealedProgramKey(filePath string, t tao.Tao, domain tao.Domain, useSimpleDomainService bool,
	caAddr string) (*tao.Keys, []byte, [][]byte, error) {

	k, derCert, err := CreateSigningKey(t)
	if err != nil || derCert == nil {
		log.Printf("InitializeSealedProgramKey: CreateSigningKey failed with error %s\n", err)
		return nil, nil, nil, err
	}

	// Get program cert.
	var programCert []byte
	var certChain [][]byte
	if useSimpleDomainService {
		domain_response, err := RequestDomainServiceCert("tcp", caAddr, k, domain.Keys.VerifyingKey)
		if err != nil || domain_response == nil {
			log.Printf("InitializeSealedProgramKey: error from RequestDomainServiceCert\n")
			return nil, nil, nil, err
		}
		programCert = domain_response.SignedCert
		certChain = domain_response.CertChain
		k.Cert, err = x509.ParseCertificate(programCert)
		if err != nil {
			log.Printf("InitializeSealedProgramKey: Can't parse certificate\n")
			return nil, nil, nil, err
		}
		k.Cert.Raw = programCert
	} else {
		cert, err := domain_service.RequestProgramCert(k.Delegation, k.VerifyingKey, "tcp", caAddr)
		if err != nil {
			return nil, nil, nil, err
		}
		k.Cert = cert
		programCert = cert.Raw
		// Cert chains?
	}

	// Serialize and save key blob
	programKeyBlob, err := tao.MarshalSignerDER(k.SigningKey)
	if err != nil {
		return nil, nil, nil, errors.New("InitializeSealedProgramKey: Can't produce signing key blob")
	}

	sealedProgramKey, err := t.Seal(programKeyBlob, tao.SealPolicyDefault)
	if err != nil {
		return nil, nil, nil, errors.New("InitializeSealedProgramKey: Can't seal signing key")
	}
	err = ioutil.WriteFile(path.Join(filePath, "sealedsigningKey"), sealedProgramKey, os.ModePerm)
	if err != nil {
		return nil, nil, nil, err
	}
	err = ioutil.WriteFile(path.Join(filePath, "signerCert"), programCert, os.ModePerm)
	if err != nil {
		return nil, nil, nil, err
	}
	/*
		FIX
		if certChain.size() > 0 {
			// Save cert chain
			FIX
			err = ioutil.WriteFile(path.Join(filePath, "certChain"), certChain, os.ModePerm)
			if err != nil {
				return nil, nil, nil, err
			}
		}
	*/
	return k, programCert, certChain, nil
}

// Load domain info for the domain and establish Clouproxy keys and properties.
// This handles reading in existing (sealed) Cloudproxy keys and properties, or,
// if this is the first call (or a call after state has been erased), this also
// handles initialization of keys and certificates including interaction with the
// domain signing service and storage of new sealed keys and certificates.
// If TaoParadigm completes without error, programObject contains all the
// Cloudproxy information needed throughout the calling program execution
// ensures that this information is sealed and stored for subsequent invocations.
//
// More generally, TaoParadigm should take a keyset type that specifies the public
// and symmetric key types and lengths but for now, its P-256 ECC and 64 bit symmetric
// keys.  It should be part of the ProgramData.
func TaoParadigm(cfg *string, filePath *string, keySetType string, useSimpleDomainService bool, caAddr string,
	programObject *TaoProgramData) error {

	// Load domain info for this domain.
	simpleDomain, err := tao.LoadDomain(*cfg, nil)
	if err != nil {
		return errors.New(fmt.Sprintln("TaoParadigm: Can't load domain. Error: ", err))
	}

	// Get policy cert.
	if simpleDomain.Keys.Cert == nil {
		return errors.New("TaoParadigm: Can't retrieve policy cert")
	}
	derPolicyCert := simpleDomain.Keys.Cert.Raw
	if derPolicyCert == nil {
		return errors.New("TaoParadigm: Can't retrieve der encoded policy cert")
	}

	// Extend tao name with policy key
	err = simpleDomain.ExtendTaoName(tao.Parent())
	if err != nil {
		return errors.New(fmt.Sprintln("TaoParadigm: Error extending name: ", err))
	}

	// Retrieve extended name.
	taoName, err := tao.Parent().GetTaoName()
	if err != nil {
		return errors.New(fmt.Sprintln("TaoParadigm: Can't extend Tao Principal name. Error: ", err))
	}
	log.Printf("TaoParadigm: my name is %s\n", taoName)

	// Get my keys and certificates.
	sealedSymmetricKey, sealedProgramKey, programCert, certChain, err :=
		LoadProgramKeys(*filePath)
	if err != nil {
		return errors.New(fmt.Sprintln("TaoParadigm: Can't retrieve existing key material. Error: ", err))
	}
	// Unseal my symmetric keys, or initialize them.
	var symKeys []byte
	var policy string
	if sealedSymmetricKey != nil {
		symKeys, policy, err = tao.Parent().Unseal(sealedSymmetricKey)
		if err != nil {
			return errors.New(fmt.Sprintln("TaoParadigm: can't unseal symmetric keys. Error: ", err))
		}
		if policy != tao.SealPolicyDefault {
			return errors.New("TaoParadigm: can't unseal symmetric keys. SealPolicy does not match.")
		}
	} else {
		symKeys, err = InitializeSealedSymmetricKeys(*filePath, tao.Parent(), SizeofSymmetricKeys)
		if err != nil {
			return errors.New(fmt.Sprintf("TaoParadigm: InitializeSealedSymmetricKeys error: %v", err))
		}
	}
	log.Printf("Unsealed symmetric keys\n")

	// Get my Program private key if present or initialize it.
	var programKey *tao.Keys
	if sealedProgramKey != nil {
		programKey, err = SigningKeyFromBlob(tao.Parent(), sealedProgramKey, programCert)
		if err != nil {
			return errors.New(fmt.Sprintln("TaoParadigm: SigningKeyFromBlob error: ", err))
		}
	} else {
		// Get Program key.
		programKey, programCert, certChain, err = InitializeSealedProgramKey(
			*filePath, tao.Parent(), *simpleDomain, useSimpleDomainService, caAddr)
		if err != nil {
			return errors.New(fmt.Sprintln("TaoParadigm: InitializeSealedSigningKey error: ", err))
		}
		if programKey == nil {
			return errors.New("TaoParadigm: InitializeSealedSigningKey error: programKey not loaded")
		}
	}
	log.Printf("TaoParadigm: Retrieved Signing key\n")

	// Initialize Program policy object.
	ok := programObject.FillTaoProgramData(keySetType, derPolicyCert, taoName.String(),
		*programKey, symKeys, programCert, certChain, filePath)
	if !ok {
		return errors.New("TaoParadigm: Can't initialize TaoProgramData")
	}

	return nil
}

// Establishes the Tao Channel for a client using the Program Key.
// This program does all the standard client side channel negotiation.
// After negotiation is complete.  ms is the bi-directional confidentiality and
// integrity protected channel.  OpenTaoChannel returns the stream (ms) for subsequent reads
// and writes as well as the server's Tao Principal Name.
func OpenTaoChannel(programObject *TaoProgramData, serverAddr *string) (
	*util.MessageStream, *string, error) {

	// Parse policy cert and make it the root of our
	// hierarchy for verifying Tao Channel peer.
	policyCert, err := x509.ParseCertificate(programObject.PolicyCert)
	if err != nil {
		return nil, nil, errors.New("OpenTaoChannel: Can't ParseCertificate")
	}
	pool := x509.NewCertPool()
	pool.AddCert(policyCert)

	// Open the Tao Channel using the Program key.
	tlsc, err := tao.EncodeTLSCert(&programObject.ProgramKey)
	if err != nil {
		log.Fatalln("OpenTaoChannel, encode error: ", err)
	}
	// TODO(manferdelli): Replace this with tao.Dial?
	conn, err := tls.Dial("tcp", *serverAddr, &tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: false,
	})
	if err != nil {
		fmt.Printf("OpenTaoChannel: Can't establish channel : %v\n", err)
		return nil, nil, errors.New("OpenTaoChannel: Can't establish channel")
	}

	peerName := policyCert.Subject.OrganizationalUnit[0]

	// Stream for Tao Channel.
	ms := util.NewMessageStream(conn)
	return ms, &peerName, nil
}

// Returns sealed symmetric key, sealed signing key,
// DER encoded program cert, cert chain, if files exist.
// Only returns errors if file exists but can't be read.
func LoadProgramKeys(filePath string) ([]byte, []byte, []byte, [][]byte, error) {
	var sealedSymmetricKey []byte
	var sealedProgramKey []byte
	var derCert []byte
	var certChain [][]byte

	_, err := os.Stat(path.Join(filePath, "sealedsymmetricKey"))
	if err != nil {
		sealedSymmetricKey = nil
	} else {
		sealedSymmetricKey, err = ioutil.ReadFile(path.Join(filePath, "sealedsymmetricKey"))
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}
	_, err = os.Stat(path.Join(filePath, "sealedsigningKey"))
	if err != nil {
		sealedProgramKey = nil
		derCert = nil
		certChain = nil
	} else {
		sealedProgramKey, err = ioutil.ReadFile(path.Join(filePath, "sealedsigningKey"))
		if err != nil {
			return nil, nil, nil, nil, err
		}
		derCert, err = ioutil.ReadFile(path.Join(filePath, "signerCert"))
		if err != nil {
			return nil, nil, nil, nil, err
		}
		// FIX
		// certChain, _ = ioutil.ReadFile(path.Join(filePath, "certChain"))
		certChain = nil
	}
	return sealedSymmetricKey, sealedProgramKey, derCert, certChain, nil
}

// Create a Program Public/Private key.
func CreateSigningKey(t tao.Tao) (*tao.Keys, []byte, error) {

	self, err := t.GetTaoName()
	k, err := tao.NewTemporaryKeys(tao.Signing)
	if k == nil || err != nil {
		return nil, nil, errors.New("Can't generate signing key")
	}

	publicString := strings.Replace(self.String(), "(", "", -1)
	publicString = strings.Replace(publicString, ")", "", -1)

	// publicString is now a canonicalized Tao Principal name
	us := "US"
	google := "Google"
	details := tao.X509Details{
		Country:      &us,
		Organization: &google,
		CommonName:   &publicString}
	subjectname := tao.NewX509Name(&details)

	derCert, err := k.SigningKey.CreateSelfSignedDER(subjectname)
	if err != nil {
		return nil, nil, errors.New("Can't self sign cert\n")
	}
	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		return nil, nil, err
	}

	// Construct statement: "ProgramKey (new key) speaksfor Principal Name"
	// ToPrincipal retrieves key's Tao Principal Name.
	k.Cert = cert
	s := &auth.Speaksfor{
		Delegate:  k.SigningKey.ToPrincipal(),
		Delegator: self}
	if s == nil {
		return nil, nil, errors.New("Can't produce speaksfor")
	}

	// Sign attestation statement
	k.Delegation, err = t.Attest(&self, nil, nil, s)
	if err != nil {
		return nil, nil, err
	}
	_, _ = auth.UnmarshalForm(k.Delegation.SerializedStatement)
	return k, derCert, nil
}

// Obtain a signing private key (usually a Program Key) from a sealed blob.
func SigningKeyFromBlob(t tao.Tao, sealedKeyBlob []byte, programCert []byte) (*tao.Keys, error) {

	// Recover public key from blob
	k := &tao.Keys{}

	cert, err := x509.ParseCertificate(programCert)
	if err != nil {
		return nil, err
	}

	/*
		 * We don't use this now.
		k.Delegation = new(tao.Attestation)
		err = proto.Unmarshal(delegateBlob, k.Delegation)
		if err != nil {
			return nil, err
		}
	*/

	signingKeyBlob, policy, err := tao.Parent().Unseal(sealedKeyBlob)
	if err != nil {
		return nil, err
	}
	if policy != tao.SealPolicyDefault {
		return nil, err
	}
	k.SigningKey, err = tao.UnmarshalSignerDER(signingKeyBlob)
	k.Cert = cert
	k.Cert.Raw = programCert
	return k, err
}

func Protect(keys []byte, in []byte) ([]byte, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]byte, len(in), len(in))
	iv := make([]byte, 16, 16)
	_, err := rand.Read(iv[0:16])
	if err != nil {
		return nil, errors.New("Protect: Can't generate iv")
	}
	encKey := keys[0:16]
	macKey := keys[16:32]
	crypter, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, errors.New("Protect: Can't make crypter")
	}
	ctr := cipher.NewCTR(crypter, iv)
	ctr.XORKeyStream(out, in)

	hm := hmac.New(sha256.New, macKey)
	hm.Write(append(iv, out...))
	calculatedHmac := hm.Sum(nil)
	return append(calculatedHmac, append(iv, out...)...), nil
}

func Unprotect(keys []byte, in []byte) ([]byte, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]byte, len(in)-48, len(in)-48)
	var iv []byte
	iv = in[32:48]
	encKey := keys[0:16]
	macKey := keys[16:32]
	crypter, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, errors.New("Unprotect: Can't make crypter")
	}
	ctr := cipher.NewCTR(crypter, iv)
	ctr.XORKeyStream(out, in[48:])

	hm := hmac.New(sha256.New, macKey)
	hm.Write(in[32:])
	calculatedHmac := hm.Sum(nil)
	if bytes.Compare(calculatedHmac, in[0:32]) != 0 {
		return nil, errors.New("Unprotect: Bad mac")
	}
	return out, nil
}
