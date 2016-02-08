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
// File: simplecommon.go

package simpleexample

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
	"flag"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"code.google.com/p/goprotobuf/proto"

	"github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
	"github.com/jlmucb/cloudproxy/util"
)

var caAddr = flag.String("caAddr", "localhost:8124", "The address to listen on")
var taoChannelAddr = flag.String("taoChannelAddr", "localhost:8124", "The address to listen on")
var configPath = flag.String("config", "tao.config", "The Tao domain config")

const SizeofSymmetricKeys = 64

type ProgramPolicy struct {
	Initialized       bool
	TaoName           string
	ThePolicyCert     []byte
	ProgramSigningKey tao.Keys
	ProgramSymKeys    []byte
	ProgramCert       []byte
}

func (pp *ProgramPolicy) InitProgramPolicy(policyCert []byte, taoName string,
		signingKey tao.Keys, symKeys []byte, programCert []byte) bool {
	log.Printf("InitProgramPolicy\n")
	pp.ThePolicyCert = policyCert
	pp.TaoName = taoName
	pp.ProgramSigningKey = signingKey
	pp.ProgramSymKeys = symKeys
	pp.ProgramCert = programCert
	pp.Initialized = true
	log.Printf("InitProgramPolicy done\n")
	return true
}

// RequestTruncatedAttestation connects to a CA instance, sends the attestation
// for an X.509 certificate, and gets back a truncated attestation with a new
// principal name based on the policy key.
func RequestKeyNegoAttestation(network, addr string, keys *tao.Keys, v *tao.Verifier) (*tao.Attestation, error) {
	if keys.Cert == nil {
		return nil, errors.New("client: can't dial with an empty client certificate\n")
	}
	tlsCert, err := taonet.EncodeTLSCert(keys)
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
	ms := util.NewMessageStream(conn)
	if _, err = ms.WriteMessage(keys.Delegation); err != nil {
		return nil, err
	}

	// Read the truncated attestation and check it.
	var a tao.Attestation
	if err := ms.ReadMessage(&a); err != nil {
		return nil, err
	}

	ok, err := v.Verify(a.SerializedStatement, tao.AttestationSigningContext, a.Signature)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("invalid attestation signature from Tao CA")
	}

	return &a, nil
}

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

// returns sealed symmetric key, sealed signing key, DER encoded cert, delegation, error
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
	log.Printf("fileproxy: Got sealedSymmetricKey\n")
	sealedSigningKey, err := ioutil.ReadFile(path + "sealedsigningKey")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	log.Printf("fileproxy: Got sealedSigningKey\n")
	derCert, err := ioutil.ReadFile(path + "signerCert")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	log.Printf("fileproxy: Got signerCert\n")
	ds, err := ioutil.ReadFile(path + "delegationBlob")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	log.Printf("LoadProgramKeys succeeded\n")
	return sealedSymmetricKey, sealedSigningKey, derCert, ds, nil
}

func CreateSigningKey(t tao.Tao) (*tao.Keys, []byte, error) {
	log.Printf("CreateSigningKey\n")
	self, err := t.GetTaoName()
	k, err := tao.NewTemporaryKeys(tao.Signing)
	if k == nil || err != nil {
		return nil, nil, errors.New("Can't generate signing key")
	}
	publicString := strings.Replace(self.String(), "(", "", -1)
	publicString = strings.Replace(publicString, ")", "", -1)
	details := tao.X509Details{
		Country:      "US",
		Organization: "Google",
		CommonName:   publicString}
	subjectname := tao.NewX509Name(details)
	derCert, err := k.SigningKey.CreateSelfSignedDER(subjectname)
	if err != nil {
		return nil, nil, errors.New("Can't self sign cert\n")
	}
	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		return nil, nil, err
	}
	k.Cert = cert
	s := &auth.Speaksfor{
		Delegate:  k.SigningKey.ToPrincipal(),
		Delegator: self}
	if s == nil {
		return nil, nil, errors.New("Can't produce speaksfor")
	}
	if k.Delegation, err = t.Attest(&self, nil, nil, s); err != nil {
		return nil, nil, err
	}
	if err == nil {
		_, _ = auth.UnmarshalForm(k.Delegation.SerializedStatement)
	}
	return k, derCert, nil
}

func InitializeSealedSymmetricKeys(path string, t tao.Tao, keysize int) ([]byte, error) {
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

func InitializeSealedSigningKey(path string, t tao.Tao, domain tao.Domain) (*tao.Keys, error) {
	log.Printf("InitializeSealedSigningKey\n")
	k, derCert, err := CreateSigningKey(t)
	if err != nil {
		log.Printf("fileproxy: CreateSigningKey failed with error %s\n", err)
		return nil, err
	}
	if derCert == nil {
		log.Printf("fileproxy: CreateSigningKey failed, no dercert\n")
		return nil, errors.New("No DER cert")
	}
	na, err := RequestKeyNegoAttestation("tcp", *caAddr, k, domain.Keys.VerifyingKey)
	if err != nil {
		log.Printf("fileproxy: error from taonet.RequestTruncatedAttestation\n")
		return nil, err
	}
	if na == nil {
		return nil, errors.New("tao returned nil attestation")
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
		return nil, errors.New("says doesnt have speaksfor message")
	}
	kprin, ok := sf.Delegate.(auth.Term)
	if ok != true {
		return nil, errors.New("speaksfor message doesnt have Delegate")
	}
	newCert := auth.Bytes(kprin.(auth.Bytes))
	k.Cert, err = x509.ParseCertificate(newCert)
	if err != nil {
		log.Printf("can't parse returned certificate", err)
		log.Printf("\n")
		return nil, err
	}
	signingKeyBlob, err := tao.MarshalSignerDER(k.SigningKey)
	if err != nil {
		return nil, errors.New("Can't produce signing key blob")
	}
	sealedSigningKey, err := t.Seal(signingKeyBlob, tao.SealPolicyDefault)
	if err != nil {
		return nil, errors.New("Can't seal signing key")
	}
	err = ioutil.WriteFile(path+"sealedsigningKey", sealedSigningKey, os.ModePerm)
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(path+"signerCert", newCert, os.ModePerm)
	if err != nil {
		return nil, err
	}
	delegateBlob, err := proto.Marshal(k.Delegation)
	if err != nil {
		return nil, errors.New("Can't seal random bytes")
	}
	err = ioutil.WriteFile(path+"delegationBlob", delegateBlob, os.ModePerm)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func SigningKeyFromBlob(t tao.Tao, sealedKeyBlob []byte, certBlob []byte,
		delegateBlob []byte) (*tao.Keys, error) {
	log.Printf("SigningKeyFromBlob\n")
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
	log.Printf("SigningKeyFromBlob: unmarshaled\n")
	signingKeyBlob, policy, err := tao.Parent().Unseal(sealedKeyBlob)
	if err != nil {
		log.Printf("fileproxy: signingkey unsealing error: %s\n", err)
	}
	if policy != tao.SealPolicyDefault {
		log.Printf("fileproxy: unexpected policy on unseal\n")
	}
	log.Printf("fileproxy: Unsealed Signing Key blob: %x\n", signingKeyBlob)
	k.SigningKey, err = tao.UnmarshalSignerDER(signingKeyBlob)
	k.Cert = cert
	return k, err
}

func PrintRequest(subject []byte, action *string, resource *string, owner []byte) {
	log.Printf("PrintRequest\n")
	if subject != nil {
		log.Printf("\tsubject: % x\n", subject)
		subjectName := PrincipalNameFromDERCert(subject)
		if subjectName != nil {
			log.Printf("\tsubject: %s\n", *subjectName)
		}
	}
	if action != nil {
		log.Printf("\taction: %s\n", *action)
	}
	if resource != nil {
		log.Printf("\tresource: %s\n", *resource)
	}
	if owner != nil {
		log.Printf("\towner: % x\n", owner)
		ownerName := PrincipalNameFromDERCert(owner)
		if ownerName != nil {
			log.Printf("\towner: %s\n", *ownerName)
		}
	}
}

func GetResponse(ms *util.MessageStream) (*string, *string, *int, error) {
	log.Printf("GetResponse\n")

	strbytes, err := ms.ReadString()

	fpMessage := new(FPMessage)
	err = proto.Unmarshal([]byte(strbytes), fpMessage)
	if err != nil {
		return nil, nil, nil, errors.New("GetResponse can't unmarshal message")
	}
	if fpMessage.MessageType == nil {
		return nil, nil, nil, errors.New("GetResponse: no message type")
	}
	if *fpMessage.MessageType != int32(MessageType_RESPONSE) {
		log.Printf("GetResponse bad type\n")
		return nil, nil, nil, errors.New("reception error")
	}
	var status *string
	var errMessage *string
	var size int

	if fpMessage.StatusOfRequest == nil {
		log.Printf("GetResponse no status\n")
		return nil, nil, nil, errors.New("reception error")
	}
	status = fpMessage.StatusOfRequest
	errMessage = fpMessage.MessageFromRequest
	if fpMessage.BufferSize == nil {
		return status, errMessage, nil, nil
	} else {
		size = int(*fpMessage.BufferSize)
		return status, errMessage, &size, nil
	}
}


func PrintResponse(status *string, message *string, size *int) {
	log.Printf("PrintResponse\n")
	if status != nil {
		log.Printf("\tstatus: %s\n", *status)
	} else {
		log.Printf("\tstatus: empty\n")
	}
	if message != nil {
		log.Printf("\tmessage: %s\n", *message)
	}
	if size != nil {
		log.Printf("\tsize: %d\n", *size)
	}
}

func SendResponse(ms *util.MessageStream, status string, errMessage string, size int) error {
	fpMessage := new(FPMessage)
	fpMessage.MessageType = proto.Int32(int32(MessageType_RESPONSE))
	fpMessage.StatusOfRequest = proto.String(status)
	fpMessage.MessageFromRequest = proto.String(errMessage)
	out, err := proto.Marshal(fpMessage)
	if err != nil {
		log.Printf("SendResponse can't encode response\n")
		return err
	}
	send := string(out)
	log.Printf("SendResponse sending %s %s %d\n", status, errMessage, len(send))
	n, err := ms.WriteString(send)
	if err != nil {
		log.Printf("SendResponse Writestring error %d\n", n, err)
		return err
	}
	return nil
}

func SendProtocolMessage(ms *util.MessageStream, size int, buf []byte) error {
	log.Printf("SendProtocolMessage\n")
	fpMessage := new(FPMessage)
	fpMessage.MessageType = proto.Int32(int32(MessageType_PROTOCOL_RESPONSE))
	fpMessage.BufferSize = proto.Int32(int32(size))
	fpMessage.TheBuffer = proto.String(string(buf))
	out, err := proto.Marshal(fpMessage)
	if err != nil {
		log.Printf("SendResponse can't encode response\n")
		return err
	}
	n, err := ms.WriteString(string(out))
	if err != nil {
		log.Printf("SendProtocolMessage Writestring error %d\n", n, err)
		return err
	}
	return nil
}

func GetProtocolMessage(ms *util.MessageStream) ([]byte, error) {
	log.Printf("GetProtocolMessage\n")
	strbytes, err := ms.ReadString()
	if err != nil {
		return nil, err
	}
	fpMessage := new(FPMessage)
	err = proto.Unmarshal([]byte(strbytes), fpMessage)
	if err != nil {
		return nil, errors.New("GetProtocolMessage can't unmarshal message")
	}
	if fpMessage.MessageType == nil {
		return nil, errors.New("GetProtocolMessage: no message type")
	}
	if *fpMessage.MessageType != int32(MessageType_PROTOCOL_RESPONSE) {
		return nil, errors.New("GetProtocolMessage: Wrong message type")
	}
	out := fpMessage.TheBuffer
	if out == nil {
		return nil, errors.New("GetProtocolMessage: empty buffer")
	}
	return []byte(*out), nil
}

