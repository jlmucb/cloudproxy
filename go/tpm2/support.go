// Copyright (c) 2014, Google Inc. All rights reserved.
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

// Package tpm2 supports direct communication with a tpm 2.0 device under Linux.

package tpm2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/golang/protobuf/proto"
)

func GetPublicKeyFromDerCert(derCert []byte) (*rsa.PublicKey, error) {
	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		return nil, err
	}

	var publicKey *rsa.PublicKey
	switch k :=  cert.PublicKey.(type) {
	case  *rsa.PublicKey:
		publicKey = k
	case  *rsa.PrivateKey:
		publicKey = &k.PublicKey
	default:
		return nil, errors.New("Wrong public key type")
	}
	return publicKey, nil
}

func GetPrivateKeyFromSerializedMessage(in []byte) (*rsa.PrivateKey, error){
	msg := new(RsaPrivateKeyMessage)
	err := proto.Unmarshal(in, msg)
	key, err := UnmarshalRsaPrivateFromProto(msg)
	if err != nil {
		return nil, errors.New("Can't unmarshal key to proto")
	}
	return key, nil
}

func GenerateCertFromKeys(signingKey *rsa.PrivateKey, signerDerPolicyCert []byte, subjectKey *rsa.PublicKey,
		subjectOrgName string, subjectCommonName string,
		serialNumber *big.Int, notBefore time.Time, notAfter time.Time) ([]byte, error){
	signingCert, err := x509.ParseCertificate(signerDerPolicyCert)
	if err != nil {
		return nil, errors.New("Can't parse signer certificate")
	}
	signTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name {
			Organization: []string{subjectOrgName},
			CommonName: subjectCommonName,
			},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: false,
	}
	derSignedCert, err := x509.CreateCertificate(rand.Reader, &signTemplate, signingCert,
		subjectKey, signingKey)
	if err != nil {
		return nil, errors.New("Can't CreateCertificate")
	}
	return derSignedCert, nil 
}

func SerializeRsaPrivateKey(key *rsa.PrivateKey) ([]byte, error) {
	msg, err := MarshalRsaPrivateToProto(key)
	if err != nil {
		return nil, errors.New("Can't marshall private key")
	}
	return []byte(proto.CompactTextString(msg)), nil
}

func DeserializeRsaPolicyKey(in []byte) (*rsa.PrivateKey, error) {
	msg := new(RsaPrivateKeyMessage)
	err := proto.Unmarshal(in, msg)
	key, err := UnmarshalRsaPrivateFromProto(msg)
	if err != nil {
		return nil, errors.New("Can't Unmarshal private key")
	}
	return key, nil
}

func PublicKeyFromPrivate(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	default:
	return nil
	}
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
	out := make([]byte, len(in) - 48, len(in) - 48)
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

func KDFA(alg uint16, key []byte, label string, contextU []byte,
		contextV []byte, bits int) ([]byte, error) {
	counter := uint32(0)
	bytes_left := (bits + 7) / 8;
	var out []byte
	for ; bytes_left > 0 ; {
		counter = counter + 1
		if alg == AlgTPM_ALG_SHA1 {
			mac := hmac.New(sha1.New, key)
			// copy counter (big Endian), label, contextU, contextV, bits (big Endian)
			outa,_ := pack([]interface{}{&counter})
			var arr [32]byte
			copy(arr[0:], label)
			arr[len(label)] = 0
			outc := append(contextU, contextV...)
			u_bits := uint32(bits)
			outd,_ := pack([]interface{}{&u_bits})
			in := append(outa, append(arr[0:len(label)+1], append(outc, outd...)...)...)
			mac.Write(in)
			out = append(out, mac.Sum(nil)...)
			bytes_left -= 20
		} else if alg == AlgTPM_ALG_SHA256 {
			mac := hmac.New(sha256.New, key)
			// copy counter (big Endian), label, contextU, contextV, bits (big Endian)
			outa, _ := pack([]interface{}{&counter})
			var arr [32]byte
			copy(arr[0:], label)
			arr[len(label)] = 0
			outc := append(contextU, contextV...)
			u_bits := uint32(bits)
			outd,_ := pack([]interface{}{&u_bits})
			in := append(outa, append(arr[0:len(label)+1],
				append(outc, outd...)...)...)
			mac.Write(in)
			out = append(out, mac.Sum(nil)...)
			bytes_left -= 32
		} else {
			return nil, errors.New("Unsupported key hmac alg")
		}
	}
	return out, nil
}

//	Return: out_hmac, output_data
func EncryptDataWithCredential(encrypt_flag bool, hash_alg_id uint16,
		unmarshaled_credential []byte, inData []byte,
		inHmac []byte) ([]byte, []byte, error) {
	var contextV []byte
	derivedKeys, err := KDFA(hash_alg_id, unmarshaled_credential,
		"PROTECT", contextV, contextV, 512)
	if err != nil {
		fmt.Printf("EncryptDataWithCredential can't derive keys\n")
		return nil, nil, errors.New("KDFA failed")
	}
	var calculatedHmac []byte
	outData := make([]byte, len(inData), len(inData))
	iv := derivedKeys[16:32]
	key := derivedKeys[0:16]
	dec, err := aes.NewCipher(key)
	ctr := cipher.NewCTR(dec, iv)
	ctr.XORKeyStream(outData, inData)

	var toHash []byte
	if encrypt_flag == true {
		toHash =  inData
	} else {
		toHash = outData
	}
	// Calculate hmac on output data
	if hash_alg_id == AlgTPM_ALG_SHA1 {
		hm := hmac.New(sha1.New, derivedKeys[48:64])
		hm.Write(toHash)
		calculatedHmac = hm.Sum(nil)
	} else if hash_alg_id == AlgTPM_ALG_SHA256 {
		hm := hmac.New(sha256.New, derivedKeys[32:64])
		hm.Write(toHash)
		calculatedHmac = hm.Sum(nil)
	} else {
		fmt.Printf("EncryptDataWithCredential unrecognized hmac alg\n")
		return nil, nil, errors.New("Unsupported Hash alg")
	}

	if encrypt_flag == false {
		if bytes.Compare(calculatedHmac, inHmac) != 0 {
			return nil, nil, errors.New("Integrity check fails")
		}
	}

	return calculatedHmac, outData, nil
}

func ComputeHashValue(alg uint16, to_hash []byte) ([]byte, error) {
	if alg ==  uint16(AlgTPM_ALG_SHA1) {
		hash := sha1.New()
		hash.Write(to_hash)
		hash_value := hash.Sum(nil)
		return hash_value, nil
	} else if alg == uint16(AlgTPM_ALG_SHA256) {
		hash:= sha256.New()
		hash.Write(to_hash)
		hash_value := hash.Sum(nil)
		return hash_value, nil
	} else {
		return nil, errors.New("unsupported hash alg")
	}
}

func SizeHash(alg_id uint16) (int) {
	if alg_id == uint16(AlgTPM_ALG_SHA1) {
		return 20
	} else if alg_id == uint16(AlgTPM_ALG_SHA256) {
		return 32
	} else {
		return -1
	}
}

func VerifyDerCert(der_cert []byte, der_signing_cert []byte) (bool, error) {
	roots := x509.NewCertPool()
	opts := x509.VerifyOptions{
		Roots:   roots,
	}

	// Verify key
	policy_cert, err := x509.ParseCertificate(der_signing_cert)
	if err != nil {
		fmt.Printf("Signing ParseCertificate fails")
		return false, err
	}
	roots.AddCert(policy_cert)
	fmt.Printf("Root cert: %x\n", der_signing_cert)

	// Verify key
	cert, err := x509.ParseCertificate(der_cert)
	if err != nil {
		fmt.Printf("Cert ParseCertificate fails")
		return false, err
	}
	fmt.Printf("Cert: %x\n", cert)

	roots.AddCert(policy_cert)
	opts.Roots = roots
	chains, err := cert.Verify(opts)
	if err != nil {
		fmt.Printf("Verify fails ", err, "\n")
		return false, err
	}
	if chains != nil {
		fmt.Printf("Verify\n")
		return true, nil
	} else {
		fmt.Printf("Verify no verify\n")
		return false, nil
	}

}

func MarshalRsaPrivateToProto(key *rsa.PrivateKey) (*RsaPrivateKeyMessage, error) {
	if key == nil {
		return nil, errors.New("No key")
	}
	msg := new(RsaPrivateKeyMessage)
	msg.PublicKey = new(RsaPublicKeyMessage)
	msg.D = key.D.Bytes()
	msg.PublicKey.Exponent = []byte{0,1,0,1}
	msg.PublicKey.Modulus = key.N.Bytes()
	l := int32(len(msg.PublicKey.Modulus) * 8)
	msg.PublicKey.BitModulusSize = &l
	// if len(key.Primes == 2 {
	// 	msg.PublicKey.P = msg.Primes[0].Bytes()
	// 	msg.PublicKey.Q = msg.Primes[1].Bytes()
	// }
	return msg, nil
}

func UnmarshalRsaPrivateFromProto(msg *RsaPrivateKeyMessage) (*rsa.PrivateKey, error) {
	if msg == nil {
		return nil, errors.New("No message")
	}
	key := new(rsa.PrivateKey)
	// key.PublicKey = new(rsa.PublicKey)
	key.D = new(big.Int)
	key.D.SetBytes(msg.D)
	key.PublicKey.N = new(big.Int)
	key.PublicKey.N.SetBytes(msg.PublicKey.Modulus)
	key.PublicKey.E = 0x10001  // Fix
	// if msg.PublicKey.P != nil && msg.PublicKey.Q != nil {
	// 	msg.Primes[0] = new(big.Int)
	// 	msg.Primes[1] = new(big.Int)
	// 	msg.Primes[0].SetBytes(msg.PublicKey.P)
	// 	msg.Primes[1].SetBytes(msg.PublicKey.Q)
	// }
	return key, nil
}

/*

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

// RequestDomainServiceCert requests the signed Program 
// Certificate from simpledomainservice.
//  TODO: This needs to change in a way that is tao supplier dependent.
//     For tpm2 we need the ekCert and the tao and we need the data
//     for ActivateCredential.
//     For tpm1.2, we need the aikCert.
func RequestDomainServiceCert(network, addr string, keys *tao.Keys,
		v *tao.Verifier) (*tao.Attestation, error) {
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
