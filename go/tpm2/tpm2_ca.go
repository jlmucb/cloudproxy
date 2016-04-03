// Copyright (c) 2014, Google, Inc. All rights reserved.
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
//

package tpm2

import (
	"crypto/rsa"
	//"errors"
	//"fmt"
	//"io"
	//"io/ioutil"
	//"math/big"
	//"time"
)

func Tpm2DomainProgramKeyServer(policyCert []byte, policyKey *rsa.PrivateKey) {
	//, signing_instructions_message *tpm2.SigningInstructionsMessage) {

	// Server response.
        // response, err := tpm.ConstructServerResponse(policyPrivateKey,
        //         derPolicyCert, *signing_instructions_message, *request)
	// cert, err := tpm.ClientDecodeServerResponse(rw, protectorHandle,
        //      tpm.Handle(*permQuoteHandle), *quoteOwnerPassword, *response)
}

func Tpm2DomainProgramKeyClient(/* Tao, */ programName string, programKey *rsa.PrivateKey,
	ekCert []byte) {
	// protoClientPrivateKey, request, err := tpm.ConstructClientRequest(rw,
        //         derEndorsementCert, tpm.Handle(*permQuoteHandle), "",
        //         *quoteOwnerPassword, prog_name)
}

/*
func PrintMessage(msg *SimpleMessage) {
	log.Printf("Message\n")
	if msg.MessageType != nil {
		log.Printf("\tmessage type: %d\n", *msg.MessageType)
	} else {
		log.Printf("\tmessage type: nil\n")
	}
	if msg.RequestType != nil {
		log.Printf("\trequest_type: %s\n", *msg.RequestType)
	} else {
		log.Printf("\trequest_type: nil\n")
	}
	if msg.Err != nil {
		log.Printf("\terror: %s\n", msg.Err)
	}
	log.Printf("\tdata: ");
	for _, data := range msg.GetData() {
		log.Printf("\t: %x\n", data);
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

// RequestDomainServiceCert requests the signed attest certificate
//  TODO: This needs to change in a way that is tao supplier dependent.
//     For tpm2 we need the ekCert and the tao and we need the data
//     for ActivateCredential.
//     For tpm1.2, we need the aikCert.
func RequestDomainServiceCert(network, addr string, keys *tao.Keys,
		v *tao.Verifier) (*tao.Attestation, error) {
	// todo: need tao name
	if keys.Cert == nil {
		return nil, errors.New("RequestDomainServiceCert: Can't dial with an empty client certificate")
	}
	// Explain what keys are used
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
	ms := util.NewMessageStream(conn)
	_, err = ms.WriteMessage(keys.Delegation)
	if err != nil {
		return nil, err
	}

	// Read the truncated attestation and check it.
	var a tao.Attestation
	err = ms.ReadMessage(&a)
	if err != nil {
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
	// Get endorsement and check it
	der_endorsement_cert := ioutil.ReadFile(*fileEndorsementCertInFileName)
	if der_endorsement_cert == nil {
		fmt.Printf("Can't read Endorsement Cert File\n")
		return
	}
	old_endorse_cert, err := x509.ParseCertificate(der_endorsement_cert)
	if err != nil {
		fmt.Printf("Can't parse endorsement certificate ", err, "\n")
		return
	}
	signeeTemplate := x509.Certificate{
		SerialNumber:tpm. GetSerialNumber(),
		Subject: old_endorse_cert.Subject,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// This seems to get the signer public key

	var endorsementPublic *rsa.PublicKey
	switch k :=  old_endorse_cert.PublicKey.(type) {
	case  *rsa.PublicKey:
		endorsementPublic = k
	case  *rsa.PrivateKey:
		endorsementPublic = &k.PublicKey
	default:
		fmt.Printf("endorsement cert is not an rsa key\n")
		return
	}

	new_der_endorsement_cert, err := x509.CreateCertificate(rand.Reader,
		&signeeTemplate, policy_cert, endorsementPublic, policyPrivateKey)
	if err != nil {
		fmt.Printf("Can't CreateCertificate ", err, "\n")
	}
	fmt.Printf("New endorsement cert: %x\n\n", new_der_endorsement_cert)

	// Save endorsement cert.
	fmt.Printf("Policy cert: %x\n\n", der_policy_cert)
	ioutil.WriteFile(*fileEndorsementCertOutFileName, new_der_endorsement_cert, 0644)

	ok, err := tpm.VerifyDerCert(new_der_endorsement_cert, der_policy_cert)
	if ok {
		fmt.Printf("Endorsement cert verifies\n")
	} else {
		fmt.Printf("Endorsement cert does not verify ", err, "\n")
	}
 */
