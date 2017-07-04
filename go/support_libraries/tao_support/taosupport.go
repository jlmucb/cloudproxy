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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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

type TaoProgramData struct {
	// true after initialization.
	Initialized bool

	// Program name.
	TaoName string

	// DER encoded policy cert for domain.
	PolicyCert []byte

	// Program Signing key.
	ProgramSigningKey *tao.Signer

	// Program Crypting Key.
	ProgramCryptingKey *tao.Crypter

	// Delegation
	Delegation *tao.Attestation

	// Program Cert.
	ProgramCert []byte

	// Cert Chain
	CertChain [][]byte

	// Path for program to read and write files.
	ProgramFilePath *string
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
	tao.ZeroBytes([]byte(pp.TaoName))
	tao.ZeroBytes(pp.PolicyCert)
	if pp.ProgramSigningKey != nil {
		// TODO(manferdelli): find out how to clear signingkey.
		// tao.ZeroBytes([]byte(*pp.ProgramKey))
	}
	if pp.ProgramCryptingKey != nil {
		// TODO(manferdelli): find out how to clear signingkey.
	}
	tao.ZeroBytes(pp.ProgramCert)
	pp.ProgramFilePath = nil
}

// RequestDomainServiceCert requests the signed Program Cert from SimpleDomainService
func RequestDomainServiceCert(network, addr string, requestingKey *tao.Signer,
		requestorCert *x509.Certificate, delegation *tao.Attestation,
		v *tao.Verifier) (*domain_policy.DomainCertResponse, error) {

	tlsCert, err := EncodeTLSCertFromSigner(requestingKey, requestorCert)
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
	request.Attestation, err = proto.Marshal(delegation)
	if err != nil {
		return nil, err
	}
	request.KeyType = requestingKey.Header.KeyType
	request.SubjectPublicKey, err = requestingKey.CanonicalKeyBytesFromSigner()
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

func SealMaterial(material []byte) ([]byte, error) {
	return tao.Parent().Seal(material, tao.SealPolicyDefault)
}

func UnsealMaterial(material []byte) ([]byte, error) {
	unsealed, _, err := tao.Parent().Unseal(material)
	return unsealed, err
}

func SerializeProgramData(programData *TaoProgramData) ([]byte, error) {
	var pd SavedProgramData
	pd.FilePath = programData.ProgramFilePath
	pd.PolicyCert = programData.PolicyCert
	pd.ProgramName = &programData.TaoName
	pd.CryptoSuite = &tao.TaoCryptoSuite
	pd.SignerCertChain = append(pd.SignerCertChain, programData.ProgramCert)
	for i := 0; i < len(programData.CertChain); i++ {
		pd.SignerCertChain = append(pd.SignerCertChain, programData.CertChain[i])
	}
	sck, err := tao.CryptoKeyFromSigner(programData.ProgramSigningKey)
	if err != nil {
		return nil, errors.New("Can't get CryptoKey from signer")
	}
	cck, err := tao.CryptoKeyFromCrypter(programData.ProgramCryptingKey)
	if err != nil {
		return nil, errors.New("Can't get CryptoKey from crypter")
	}
	pd.SigningKeyBlob = tao.MarshalCryptoKey(*sck)
	pd.CryptingKeyBlob = tao.MarshalCryptoKey(*cck)
	pd.Delegation, err  = proto.Marshal(programData.Delegation)
	if err != nil {
		return nil, errors.New("Can't marshal delegation")
	}
	unsealed, err := proto.Marshal(&pd)
	if err != nil {
		return nil, errors.New("Can't marshal SavedProgramData")
	}
	sealed, err := SealMaterial(unsealed)
	if err != nil {
		return nil, errors.New("Can't seal marshalled SavedProgramData")
	}
	return sealed, nil
}

func SaveProgramData(fileName string, programObject *TaoProgramData) error {
	b, err := SerializeProgramData(programObject)
	if err != nil {
		return errors.New("Can't SerializeProgramData")
	}
	err = ioutil.WriteFile(fileName, b,  os.ModePerm)
	if err != nil {
		return errors.New("Error writing program data")
	}
	certFileName := fileName +  "_cert"
	err = ioutil.WriteFile(certFileName, []byte(programObject.ProgramCert), os.ModePerm)
	if err != nil {
		return errors.New("Error writing cert")
	}
	return nil
}

func InitProgramKeys(d *tao.Domain, caAddr string, useSimpleDomainService bool,
		 programData *TaoProgramData) error {
	signerKeyType := tao.SignerTypeFromSuiteName(tao.TaoCryptoSuite)
	if signerKeyType == nil {
		return errors.New(fmt.Sprintln("InitProgramKeys: Can't get signer type\n"))
	}
	crypterKeyType := tao.CrypterTypeFromSuiteName(tao.TaoCryptoSuite)
	if crypterKeyType == nil {
		return errors.New(fmt.Sprintln("InitProgramKeys: Can't get crypter type\n"))
	}
	symTotalKeySize := tao.CombinedKeySizeFromAlgorithmName(*crypterKeyType)
	if symTotalKeySize == nil {
		return errors.New(fmt.Sprintln("InitProgramKeys: Can't get crypto suite crypter size\n"))
	}
	keyName := path.Join(programData.TaoName, "_Signer")
	keyEpoch := int32(1)
	keyPurpose := "signing"
	keyStatus := "active"
	sck := tao.GenerateCryptoKey(*signerKeyType, &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if sck == nil {
		return errors.New("InitProgramKeys: Can't generate signer\n")
	}
	programData.ProgramSigningKey = tao.SignerFromCryptoKey(*sck)
	keyName = path.Join(programData.TaoName, "_Crypter")
	keyPurpose = "crypting"
	cck := tao.GenerateCryptoKey(*crypterKeyType, &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cck == nil {
		return errors.New("InitProgramKeys: Can't generate crypter\n")
	}
	programData.ProgramCryptingKey = tao.CrypterFromCryptoKey(*cck)

	self, err := tao.Parent().GetTaoName()
	if err != nil {
		return err
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

	pkInt := tao.PublicKeyAlgFromSignerAlg(*signerKeyType)
	sigInt := tao.SignatureAlgFromSignerAlg(*signerKeyType)

	requestorCert, err := programData.ProgramSigningKey.CreateSelfSignedX509(pkInt, sigInt, int64(1), subjectname)
	if err != nil {
		return err
	}

	// Construct statement: "ProgramKey speaksfor Principal Name"
	// ToPrincipal retrieves key's Tao Principal Name.
	s := &auth.Speaksfor {
		Delegate:  programData.ProgramSigningKey.ToPrincipal(),
		Delegator: self,
		}
	if s == nil {
		return errors.New("Can't produce speaksfor")
	}

	// Sign attestation statement
	programData.Delegation, err = tao.Parent().Attest(&self, nil, nil, s)
	if err != nil {
		return err
	}

	// SerializedStatement?
	var programCert []byte
	if useSimpleDomainService {
		domain_response, err := RequestDomainServiceCert("tcp", caAddr,
			programData.ProgramSigningKey, requestorCert,
			programData.Delegation, d.Keys.VerifyingKey)
		if err != nil || domain_response == nil {
			log.Printf("InitProgramKeys: error from RequestDomainServiceCert\n")
			return err
		}
		programCert = domain_response.SignedCert
		for i := 0; i < len(domain_response.CertChain); i++ {
			programData.CertChain = append(programData.CertChain, domain_response.CertChain[i])
		}
		_, err = x509.ParseCertificate(programCert)
		if err != nil {
			log.Printf("InitProgramKeys: Can't parse certificate\n")
			return err
		}
		programData.ProgramCert = programCert
	} else {
		signedCert, err := domain_service.RequestProgramCert(programData.Delegation, programData.ProgramSigningKey.GetVerifierFromSigner(), "tcp", caAddr)
		if err != nil {
			return err
		}
		programData.ProgramCert = signedCert.Raw
		// Cert chains?
	}

	return nil
}

func DeserializeProgramData(buf []byte, programObject *TaoProgramData) error {
	unsealed, err := UnsealMaterial(buf)
	if err != nil {
		return errors.New("Can't unseal program material")
	}
	var savedProgramData SavedProgramData
	err = proto.Unmarshal(unsealed, &savedProgramData)
	if err != nil {
		return errors.New("Can't unmarshal program material")
	}
	if savedProgramData.FilePath !=  nil && 
		*programObject.ProgramFilePath != *savedProgramData.FilePath {
	}
	if !bytes.Equal(programObject.PolicyCert, savedProgramData.PolicyCert) {
	}
	if savedProgramData.ProgramName !=  nil && 
		programObject.TaoName != *savedProgramData.ProgramName {
	}
	if savedProgramData.CryptoSuite !=  nil && 
		*savedProgramData.CryptoSuite != tao.TaoCryptoSuite {
	}
	sck, err := tao.UnmarshalCryptoKey(savedProgramData.SigningKeyBlob)
	if err != nil {
		return errors.New("Can't get cryptokey for signing key")
	}
	programObject.ProgramSigningKey = tao.SignerFromCryptoKey(*sck)
	cck, err := tao.UnmarshalCryptoKey(savedProgramData.CryptingKeyBlob)
	if err != nil {
		return errors.New("Can't get cryptokey for crypting key")
	}
	programObject.ProgramCryptingKey = tao.CrypterFromCryptoKey(*cck)

	if len(savedProgramData.SignerCertChain) > 0 {
		programObject.ProgramCert = savedProgramData.SignerCertChain[0]
	}

	for i := 0; i < len(savedProgramData.SignerCertChain) - 1; i++ {
		programObject.CertChain= append(programObject.CertChain, savedProgramData.SignerCertChain[i + 1])
	}
	programObject.Delegation = new(tao.Attestation)
	err  = proto.Unmarshal(savedProgramData.Delegation, programObject.Delegation)
	if err != nil {
		return err
	}
	return nil
}

func GetProgramData(d *tao.Domain, caAddr string, progPath string, useSimpleDomainService bool,
		programObject *TaoProgramData) error {

	fileName := path.Join(progPath, "protectedProgramKeys")
	programInfoBlob, err := ioutil.ReadFile(fileName)
	if err == nil {
		err = DeserializeProgramData(programInfoBlob, programObject)
		if err != nil {
			return err
		}
	} else {
		// FIX, should pass useSimpleDomainService flag
		err := InitProgramKeys(d, caAddr, true, programObject)
		if err != nil {
			return err
		}
		_= SaveProgramData(fileName, programObject)
	}
	return nil
}

// cfg is policy domain config info
// filePath is path to program data
func TaoParadigm(cfg *string, filePath *string, useSimpleDomainService bool, caAddr string,
	programObject *TaoProgramData) error {

	// Load domain info for this domain.
	simpleDomain, err := tao.LoadDomain(*cfg, nil)
	if err != nil {
		return errors.New(fmt.Sprintln("TaoParadigm: Can't load domain. Error: ", err))
	}

	// Get policy cert.
	if simpleDomain.Keys.Cert == nil || simpleDomain.Keys.Cert.Raw == nil {
		return errors.New("TaoParadigm: Can't retrieve policy cert")
	}
	programObject.PolicyCert = simpleDomain.Keys.Cert.Raw


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
	programObject.TaoName = taoName.String()
	programObject.ProgramFilePath = filePath 
	log.Printf("TaoParadigm: my name is %s\n", taoName)

	err = GetProgramData(simpleDomain, caAddr, *filePath, useSimpleDomainService, programObject)
	if err != nil {
		return err
	}
	programObject.Initialized = true
	return nil
}

// EncodeTLSCert combines a signing key and a certificate in a single tls
// certificate suitable for a TLS config.
func EncodeTLSCertFromSigner(s *tao.Signer, cert *x509.Certificate) (*tls.Certificate, error) {
        if cert == nil {
                return nil, fmt.Errorf("client: can't encode a nil certificate")
        }
        certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
        keyBytes, err := tao.MarshalSignerDER(s)
        if err != nil {
                return nil, err
        }
        keyPem := pem.EncodeToMemory(&pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: keyBytes})

        tlsCert, err := tls.X509KeyPair(certPem, keyPem)
        if err != nil {
                return nil, fmt.Errorf("can't parse cert: %s\n", err.Error())
        }
        return &tlsCert, nil
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
	cert, err := x509.ParseCertificate(programObject.ProgramCert)
	if err != nil {
		return nil, nil, errors.New("OpenTaoChannel: Can't ParseCertificate")
	}
	pool := x509.NewCertPool()
	pool.AddCert(policyCert)

	// Open the Tao Channel using the Program key.
	tlsc, err := EncodeTLSCertFromSigner(programObject.ProgramSigningKey, cert)
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
