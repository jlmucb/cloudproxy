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

package taosupport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/golang/protobuf/proto"

	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

var caAddr = flag.String("caAddr", "localhost:8124", "The address to listen on")
var taoChannelAddr = flag.String("taoChannelAddr", "localhost:8124", "The address to listen on")
var configPath = flag.String("config", "tao.config", "The Tao domain config")

const SizeofSymmetricKeys = 64

type TaoProgramData struct {
	Initialized       bool
	TaoName           string
	PolicyCert        []byte
	ProgramKey        tao.Keys
	ProgramSymKeys    []byte
	ProgramCert       []byte
}

// RequestTruncatedAttestation connects to a CA instance, sends the attestation
// for an X.509 certificate, and gets back a truncated attestation with a new
// principal name based on the policy key.
func RequestKeyNegoAttestation(network, addr string, keys *tao.Keys, v *tao.Verifier) (*tao.Attestation,
		error) {
	if keys.Cert == nil {
		return nil, errors.New("RequestKeyNegoAttestation: Can't dial with an empty client certificate")
	}
	// Explain taonet and what keys are used
	tlsCert, err := tao.EncodeTLSCert(keys)
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

	// Tao handshake: send client delegation.
	// TODO: Explain delegation
	ms := util.NewMessageStream(conn)
	if _, err = ms.WriteMessage(keys.Delegation); err != nil {
		return nil, err
	}

	// Read the truncated attestation and check it.
	var a tao.Attestation
	if err := ms.ReadMessage(&a); err != nil {
		return nil, err
	}

	// Explain Verify and what keys are used.
	ok, err := v.Verify(a.SerializedStatement, tao.AttestationSigningContext, a.Signature)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("invalid attestation signature from Tao CA")
	}

	return &a, nil
}

func InitializeSealedSymmetricKeys(path string, t tao.Tao, keysize int) ([]byte, error) {
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
	ioutil.WriteFile(path+"sealedsymmetrickey", sealed, os.ModePerm)
	return unsealed, nil
}

func InitializeSealedProgramKey(path string, t tao.Tao, domain tao.Domain) (*tao.Keys, error) {
	k, derCert, err := CreateSigningKey(t)
	if err != nil  || derCert == nil{
		log.Printf("InitializeSealedProgramKey: CreateSigningKey failed with error %s\n", err)
		return nil, err
	}

	// Request attestations.  Policy key is verifier.
	na, err := RequestKeyNegoAttestation("tcp", *caAddr, k, domain.Keys.VerifyingKey)
	if err != nil || na == nil {
		log.Printf("fileproxy: error from taonet.RequestTruncatedAttestation\n")
		return nil, err
	}
	k.Delegation = na
	pa, _ := auth.UnmarshalForm(na.SerializedStatement)
	var saysStatement *auth.Says
	if ptr, ok := pa.(*auth.Says); ok {
		saysStatement = ptr
	} else if val, ok := pa.(auth.Says); ok {
		saysStatement = &val
	}
	sf, ok := saysStatement.Message.(auth.Speaksfor)
	if ok != true {
		return nil, errors.New("InitializeSealedProgramKey: says doesnt have speaksfor message")
	}
	kprin, ok := sf.Delegate.(auth.Term)
	if ok != true {
		return nil, errors.New("InitializeSealedProgramKey: speaksfor message doesn't have Delegate")
	}
	newCert := auth.Bytes(kprin.(auth.Bytes))
	k.Cert, err = x509.ParseCertificate(newCert)
	if err != nil {
		return nil, err
	}
	programKeyBlob, err := tao.MarshalSignerDER(k.SigningKey)
	if err != nil {
		return nil, errors.New("InitializeSealedProgramKey: Can't produce signing key blob")
	}
	sealedProgramKey, err := t.Seal(programKeyBlob, tao.SealPolicyDefault)
	if err != nil {
		return nil, errors.New("InitializeSealedProgramKey: Can't seal signing key")
	}
	err = ioutil.WriteFile(path+"sealedsigningKey", sealedProgramKey, os.ModePerm)
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(path+"signerCert", newCert, os.ModePerm)
	if err != nil {
		return nil, err
	}
	delegateBlob, err := proto.Marshal(k.Delegation)
	if err != nil {
		return nil, errors.New("InitializeSealedProgramKey: Can't seal random bytes")
	}
	err = ioutil.WriteFile(path+"delegationBlob", delegateBlob, os.ModePerm)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func (pp *TaoProgramData) InitTaoProgramData(policyCert []byte, taoName string,
		programKey tao.Keys, symKeys []byte, programCert []byte) bool {
	pp.PolicyCert = policyCert
	pp.TaoName = taoName
	pp.ProgramKey = programKey
	pp.ProgramSymKeys = symKeys
	pp.ProgramCert = programCert
	pp.Initialized = true
	return true
}

func TaoParadigm(path *string, cfg *string, programObject *TaoProgramData) (error) {

	// Load domain info for this domain.
	simpleDomain, err := tao.LoadDomain(*cfg, nil)
	if err != nil {
		return errors.New("TaoParadigm: Can't load domain")
	}

	// Get policy cert.
	if simpleDomain.Keys.Cert == nil {
		return errors.New("TaoParadigm: Can't retrieve policy cert")
	}
	derPolicyCert := simpleDomain.Keys.Cert.Raw
	if derPolicyCert == nil {
		return errors.New("TaoParadigm: Can't retrieve der encoded policy cert")
	}

	// Extend my Tao Principal name with policy key.
	e := auth.PrinExt{Name: "simpleclient_version_1"}
	err = tao.Parent().ExtendTaoName(auth.SubPrin{e})
	if err != nil {
		return errors.New("TaoParadigm: Can't extend name")
	}

	// Retrieve extended name.
	taoName, err := tao.Parent().GetTaoName()
	if err != nil {
		return errors.New("TaoParadigm: Can't extern Tao Principal name")
	}
	log.Printf("TaoParadigm: my name is %s\n", taoName)

	// Get my keys and certificates.
	sealedSymmetricKey, sealedProgramKey, programCert, delegation, err :=
		LoadProgramKeys(*path)
	if err != nil {
		return errors.New("TaoParadigm: Can't retrieve key material")
	}

	// Unseal my symmetric keys, or initialize them.
	var symKeys []byte
	var policy string
	if sealedSymmetricKey != nil {
		symKeys, policy, err = tao.Parent().Unseal(sealedSymmetricKey)
		if err != nil || policy != tao.SealPolicyDefault {
			return errors.New("TaoParadigm: can't unseal symmetric keys")
		}
	} else {
		symKeys, err = InitializeSealedSymmetricKeys(*path, tao.Parent(),
			SizeofSymmetricKeys)
		if err != nil {
			return errors.New("TaoParadigm: InitializeSealedSymmetricKeys error")
		}
	}
	log.Printf("Unsealed symmetric keys: % x\n", symKeys)

	// Get my Program private key if present or initialize it.
	var programKey *tao.Keys
	if sealedProgramKey != nil {
		programKey, err = SigningKeyFromBlob(tao.Parent(),
			sealedProgramKey, programCert, delegation)
		if err != nil {
			return errors.New("TaoParadigm: SigningKeyFromBlob error")
		}
	} else {
		// Get Program key.
		programKey, err = InitializeSealedProgramKey(
			*path, tao.Parent(), *simpleDomain)
		if err != nil || programKey == nil {
			return errors.New("TaoParadigm: InitializeSealedSigningKey error")
		}
	}
	log.Printf("TaoParadigm: Retrieved Signing key: % x\n", *programKey)

	// Initialize Program policy object.
	ok := programObject.InitTaoProgramData(derPolicyCert, taoName.String(),
		*programKey, symKeys, programCert)
	if !ok {
		return errors.New("TaoParadigm: Can't initialize TaoProgramData")
	}
	return nil
}

// Return connection and peer name.
func OpenTaoChannel(programObject *TaoProgramData, serverAddr *string) (
		*util.MessageStream, *string, error) {

	// Parse policy cert and make it the root of our heierarchy for verifying
	// Tao Channel peer.
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
	conn, err := tls.Dial("tcp", *serverAddr, &tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: false,
	})
	if err != nil {
		return nil, nil, errors.New("OpenTaoChannel: Can't establish channel")
	}

	peerName := ""

	// Stream for Tao Channel.
	ms := util.NewMessageStream(conn)
	return ms, &peerName, nil 
}


// Support functions

func ZeroBytes(buf []byte) {
	n := len(buf)
	for i := 0; i < n; i++ {
		buf[i] = 0
	}
}

func PrincipalNameFromDERCert(derCert []byte) *string {
	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		log.Printf("PrincipalNameFromDERCert: Can't get name from certificate\n")
		return nil
	}
	cn := cert.Subject.CommonName
	return &cn
}

// Returns sealed symmetric key, sealed signing key, DER encoded cert, delegation, error.
func LoadProgramKeys(path string) ([]byte, []byte, []byte, []byte, error) {
	_, err := os.Stat(path + "sealedsymmetrickey")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	_, err = os.Stat(path + "sealedsigningKey")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	_, err = os.Stat(path + "signerCert")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	sealedSymmetricKey, err := ioutil.ReadFile(path + "sealedsymmetricKey")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	sealedProgramKey, err := ioutil.ReadFile(path + "sealedsigningKey")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	derCert, err := ioutil.ReadFile(path + "signerCert")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	ds, err := ioutil.ReadFile(path + "delegationBlob")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return sealedSymmetricKey, sealedProgramKey, derCert, ds, nil
}

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

func SigningKeyFromBlob(t tao.Tao, sealedKeyBlob []byte, certBlob []byte,
		delegateBlob []byte) (*tao.Keys, error) {

	// Recover public key from blob

	k := &tao.Keys{}
	cert, err := x509.ParseCertificate(certBlob)
	if err != nil {
		return nil, err
	}
	k.Cert = cert
	k.Delegation = new(tao.Attestation)
	err = proto.Unmarshal(delegateBlob, k.Delegation)
	if err != nil {
		return nil, err
	}
	signingKeyBlob, policy, err := tao.Parent().Unseal(sealedKeyBlob)
	if err != nil {
		return nil, err
	}
	if policy != tao.SealPolicyDefault {
		return nil, err
	}
	k.SigningKey, err = tao.UnmarshalSignerDER(signingKeyBlob)
	k.Cert = cert
	return k, err
}

func PrintMessage(msg *SimpleMessage) {
	log.Printf("Message\n")
	log.Printf("\tmessage type: %d\n", msg.MessageType)
	log.Printf("\trequest_type: %s\n", msg.RequestType)
	if msg.Err != nil {
		log.Printf("\terror: %s\n", msg.Err)
	}
	log.Printf("\tdata: ");
	for _, data := range msg.GetData() {
		log.Printf("\t\t: %x\n", data);
	}
	log.Printf("\n")
}

func SendMessage(ms *util.MessageStream, msg *SimpleMessage) (error) {
	out, err := proto.Marshal(msg)
	if err != nil {
		return errors.New("SendRequest: Can't encode response")
	}
	send := string(out)
	_, err = ms.WriteString(send)
	if err != nil {
		return errors.New("SendResponse: Writestring error")
	}
	return nil
}

func GetMessage(ms *util.MessageStream) (*SimpleMessage,
		error) {
	resp, err := ms.ReadString()
	if err != nil {
		return nil, err
	}
	msg := new(SimpleMessage)
	err = proto.Unmarshal([]byte(resp), msg)
	if err != nil {
		return nil, errors.New("GetResponse: Can't unmarshal message")
	}
	return msg, nil
}

func SendRequest(ms *util.MessageStream, msg *SimpleMessage) (error) {
	m1 := int32(MessageType_REQUEST)
	msg.MessageType = &m1
	return SendMessage(ms, msg)
}

func SendResponse(ms *util.MessageStream, msg *SimpleMessage) (error) {
	m1 := int32(MessageType_RESPONSE)
	msg.MessageType = &m1
	return SendMessage(ms, msg)
}

func GetRequest(ms *util.MessageStream) (*SimpleMessage, error) {
	msg, err := GetMessage(ms)
	if err != nil || *msg.MessageType != int32(MessageType_REQUEST) {
		return nil, errors.New("GetResponse: reception error")
	}
	return msg, nil
}

func GetResponse(ms *util.MessageStream) (*SimpleMessage, error) {
	msg, err := GetMessage(ms)
	if err != nil || *msg.MessageType != int32(MessageType_RESPONSE) {
		return nil, errors.New("GetResponse: reception error")
	}
	return msg, nil
}

