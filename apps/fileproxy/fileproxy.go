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

package fileproxy

import (
	//"bufio"
	//"crypto/tls"
	//"crypto/x509"
	//"crypto/x509/pkix"
	"errors"
	"io/ioutil"
	"flag"
	"fmt"
	// "net"
	"os"
	// "strings"

	"github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	//taonet "github.com/jlmucb/cloudproxy/tao/net"
)

var serverAddr string // see main()
var configPath = flag.String("config", "tao.config", "The Tao domain config")
var ca = flag.String("ca", "", "address for Tao CA, if any")
var subprinRule = "(forall P: forall Hash: TrustedProgramHash(Hash) and Subprin(P, %v, Hash) implies MemberProgram(P))"
var argsRule = "(forall Y: forall P: forall S: MemberProgram(P) and TrustedArgs(S) and Subprin(Y, P, S) implies Authorized(Y, \"Execute\"))"
var demoRule = "TrustedArgs(ext.Args(%s))"

// returns sealed symmetric key, sealed signing key, DER encoded cert
func GetMyCryptoMaterial(path string) ([]byte, []byte,  []byte, error) {
	// stat domain.config
	fileinfo, err:= os.Stat(path+"sealedsymmetrickey")
	if(err!=nil) {
		return nil, nil, nil, err
	}
	fmt.Printf("Size of %s is %d\n", path+"sealedsymmetrickey", fileinfo.Size())
	fileinfo, err= os.Stat(path+"sealedsigning")
	if(err!=nil) {
		return nil, nil, nil, err
	}
	fmt.Printf("Size of %s is %d\n", path+"sealedsigningkey", fileinfo.Size())
	fileinfo, err= os.Stat(path+"cert")
	if(err!=nil) {
		return nil, nil, nil, err
	}
	fmt.Printf("Size of %s is %d\n", path+"cert", fileinfo.Size())

	sealedSymmetricKey, err := ioutil.ReadFile(path+"sealedsymmetrickey")
	if(err!=nil) {
		return nil, nil, nil, err
	}
	sealedSigningKey, err := ioutil.ReadFile(path+"signer")
	if(err!=nil) {
		return nil, nil, nil, err
	}
	derCert, err := ioutil.ReadFile(path+"cert")
	if(err!=nil) {
	return nil, nil, nil, err
	}
	return   sealedSymmetricKey,  sealedSigningKey, derCert, nil
}

func MakeSigningKey(t tao.Tao) (*tao.Keys, []byte,  error) {
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
	der_cert, err := k.SigningKey.CreateSelfSignedDER(subjectname)
	if(err!=nil) {
		return nil, nil,errors.New("Can't self sign cert\n")
	}
	fmt.Printf("der_cert: % x\n", der_cert);
	fmt.Printf("\n")
	// cert, err := x509.ParseCertificate(der)
	signingKeyBlob, err:= tao.MarshalSignerDER(k.SigningKey)
	// seal and save it
	// UnmarshalSignerDER(signer []byte) (*Signer, error)
	// Save DER in Cert
	if(signingKeyBlob==nil) {
		return nil, nil, errors.New("Cant produce signing key blob")
	}
	return k, der_cert, nil
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

func InitializeSealedSigningKey(path string, t tao.Tao) ([]byte , []byte , error) {
	// NewTemporaryTaoDelegatedKeys(keyTypes KeyType, t Tao) (*Keys, error)
	return nil, nil, errors.New("InitializeSealedSymmetricKeys not implemented")
}


