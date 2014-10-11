// Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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
// File: fileproxy.go

package fileproxy

import (
	"crypto/x509"
	"errors"
	"io/ioutil"
	"flag"
	"fmt"
	"net"
	"os"
	"code.google.com/p/goprotobuf/proto"
	"github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
)

var caAddr = flag.String("ca", "localhost:8124", "The address to listen on")
var taoChannelAddr = flag.String("ca", "localhost:8124", "The address to listen on")
var configPath = flag.String("config", "tao.config", "The Tao domain config")
var ca = flag.String("ca", "", "address for Tao CA, if any")
var subprinRule = "(forall P: forall Hash: TrustedProgramHash(Hash) and Subprin(P, %v, Hash) implies MemberProgram(P))"
var argsRule = "(forall Y: forall P: forall S: MemberProgram(P) and TrustedArgs(S) and Subprin(Y, P, S) implies Authorized(Y, \"Execute\"))"
var demoRule = "TrustedArgs(ext.Args(%s))"

/*
n := binary.BigEndian.Uint32(sizebytes[:])
max := ms.MaxMessageSize
// We also check for int(n) to overflow so allocation below doesn't fail.
if int(n) < 0 || (max > 0 && int(n) > max) {
glog.Errorf("String on wire is too large: %d bytes\n", n)
return "", Logged(ErrMessageTooLarge)
}
strbytes := make([]byte, int(n))
*/

func ZeroBytes(buf []byte) {
	n:= len(buf)
	for i:=0;i<n;i++ {
		buf[i]= 0
	}
}

// returns sealed symmetric key, sealed signing key, DER encoded cert
func GetMyCryptoMaterial(path string) ([]byte, []byte,  []byte, []byte, error) {
	// stat domain.config
	fileinfo, err:= os.Stat(path+"sealedsymmetrickey")
	if(err!=nil) {
		return nil, nil, nil, nil, err
	}
	fmt.Printf("Size of %s is %d\n", path+"sealedsymmetrickey", fileinfo.Size())
	fileinfo, err= os.Stat(path+"sealedsigning")
	if(err!=nil) {
		return nil, nil, nil, nil, err
	}
	fmt.Printf("Size of %s is %d\n", path+"sealedsigningkey", fileinfo.Size())
	fileinfo, err= os.Stat(path+"cert")
	if(err!=nil) {
		return nil, nil, nil, nil, err
	}
	fmt.Printf("Size of %s is %d\n", path+"cert", fileinfo.Size())

	sealedSymmetricKey, err := ioutil.ReadFile(path+"sealedsymmetrickey")
	if(err!=nil) {
		return nil, nil, nil, nil, err
	}
	sealedSigningKey, err := ioutil.ReadFile(path+"signer")
	if(err!=nil) {
		return nil, nil, nil, nil, err
	}
	derCert, err := ioutil.ReadFile(path+"cert")
	if(err!=nil) {
		return nil, nil, nil, nil, err
	}
	ds, err := ioutil.ReadFile(path+"delegation")
	if ds!=nil || err != nil {
		return nil, nil, nil, nil, err
	}
	return   sealedSymmetricKey, sealedSigningKey, ds, derCert, nil
}

func CreateSigningKey(t tao.Tao) (*tao.Keys, []byte,  error) {
	self, err := t.GetTaoName()
	k, err:=  tao.NewTemporaryKeys(tao.Signing)
	if k==nil || k.SigningKey != nil || err!= nil {
		return nil, nil, errors.New("Cant generate signing key")
	}
	s := &auth.Speaksfor{
		Delegate:  k.SigningKey.ToPrincipal(),
		Delegator: self,}
	if(s==nil) {
		return nil, nil, errors.New("Cant produce speaksfor")
	}
	if k.Delegation, err = t.Attest(&self, nil, nil, s); err != nil {
		return nil, nil, err
	}
	details := tao.X509Details {
		Country: "US",
		Organization: "Google",
		CommonName: self.String(), }
	subjectname:= tao.NewX509Name(details)
	derCert, err := k.SigningKey.CreateSelfSignedDER(subjectname)
	if(err!=nil) {
		return nil, nil,errors.New("Can't self sign cert\n")
	}
	fmt.Printf("derCert: % x\n", derCert);
	fmt.Printf("\n")
	cert, err := x509.ParseCertificate(derCert)
	if(err!=nil) {
		return nil, nil, err
	}
	k.Cert= cert
	return k, derCert, nil
}

func InitializeSealedSymmetricKeys(path string, t tao.Tao, keysize int) ([]byte, error) {
	unsealed, err := tao.Parent().GetRandomBytes(keysize)
	if err != nil {
		return nil, errors.New("Cant get random bytes")
	}
	sealed, err := tao.Parent().Seal(unsealed, tao.SealPolicyDefault)
	if err != nil {
	return nil, errors.New("Cant seal random bytes")
	}
	ioutil.WriteFile(path+"sealedsymmetrickey", sealed, os.ModePerm)
	return unsealed, nil
}

func InitializeSealedSigningKey(path string, t tao.Tao, domain tao.Domain) (*tao.Keys, error) {
	k, derCert, err:= CreateSigningKey(t)
	if (err!=nil || derCert==nil) {
		fmt.Printf("CreateSigningKey failed\n")
	}
	// I need the signed cert as well as the delegation
	na, err := taonet.RequestTruncatedAttestation("tcp", *ca, k, domain.Keys.VerifyingKey)
	if(err!=nil || na==nil) {
		return nil, errors.New("keynegoserver attestation failed")
	}
	k.Delegation= na
	signingKeyBlob, err:= tao.MarshalSignerDER(k.SigningKey)
	if(err!=nil) {
		return nil, errors.New("Cant produce signing key blob")
	}
	sealedSigningKey, err := t.Seal(signingKeyBlob, tao.SealPolicyDefault)
	if err != nil {
		return nil, errors.New("Cant seal signing ken")
	}
	err= ioutil.WriteFile(path+"signer", sealedSigningKey, os.ModePerm)
	if(err!=nil) {
		return nil, err
	}
	k.Cert, err= x509.ParseCertificate(derCert)
	err= ioutil.WriteFile(path+"cert", derCert, os.ModePerm)
	if(err!=nil) {
		return nil, err
	}
	delegateBlob, err:= proto.Marshal(k.Delegation)
	if err != nil {
		return nil, errors.New("Cant seal random bytes")
	}
	err= ioutil.WriteFile(path+"delegation", delegateBlob, os.ModePerm)
	if(err!=nil) {
		return nil, err
	}
	return k, nil
}

func SigningKeyFromBlob(t tao.Tao, sealedKeyBlob []byte, delegateBlob []byte, certBlob []byte) (*tao.Keys, error) {
	k:= &tao.Keys{};

	// k.SetMyKeyPath(path)
	k.SetKeyType(tao.Signing)
	cert, err:= x509.ParseCertificate(certBlob)
	if(err!=nil) {
		return nil,err
	}
	k.Cert= cert
	k.Delegation = new(tao.Attestation)
	err= proto.Unmarshal(delegateBlob, k.Delegation)
	if err != nil {
		return nil, err
	}
	signingKeyBlob, policy, err := tao.Parent().Unseal(sealedKeyBlob)
	if err != nil {
		fmt.Printf("fileclient: symkey unsealing error: %s\n")
	}
	if policy != tao.SealPolicyDefault {
		fmt.Printf("fileclient: unexpected policy on unseal\n")
	}
	fmt.Printf("Unsealed Signing Key blob: % x\n", signingKeyBlob)
	k.SigningKey, err= tao.UnmarshalSignerDER(signingKeyBlob)
	return k, err
}

func EstablishPeerChannel(t tao.Tao, keys tao.Keys) (net.Conn, error) {
	return nil, errors.New("Channel Establishment fails")
}

func SendFile(conn net.Conn, creds []byte, filename string, keys []byte) error {
	return errors.New("SendFile request not implemented")
}

func GetFile(conn net.Conn, creds []byte, filename string, keys []byte) error {
	return errors.New("GetFile request not implemented")
}

func CreateFile(conn net.Conn, creds []byte, filename string) error {
	return errors.New("CreateFile request not implemented")
}

func DeleteFile(conn net.Conn, creds []byte, filename string) error {
	return errors.New("CreateFile request not implemented")
}

func AddFilePermissions(conn net.Conn, creds []byte, filename string) error {
	return errors.New("AddFilePermissions request not implemented")
}

