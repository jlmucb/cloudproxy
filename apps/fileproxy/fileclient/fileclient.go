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
// File: fileclient.go

package main

import (
	"flag"
	"fmt"

	"github.com/jlmucb/cloudproxy/apps/fileproxy"
	tao "github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	"github.com/jlmucb/cloudproxy/util"

	"code.google.com/p/goprotobuf/proto"
	"crypto/tls"
	"crypto/x509"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
	"io/ioutil"
)

var hostcfg = flag.String("../hostdomain/tao.config", "../hostdomain/tao.config", "path to host tao configuration")
var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var fileclientPath = flag.String("./fileclient_files/", "./fileclient_files/", "fileclient directory")
var serverAddr string
var fileclientFilePath = flag.String("./fileclient_files/stored_files/", "./fileclient_files/stored_files/",
	"fileclient file directory")
var testFile = flag.String("originalTestFile", "originalTestFile", "test file")
var fileclientKeyPath = flag.String("usercreds/", "usercreds/", "user keys and certs")

var DerPolicyCert []byte
var SigningKey tao.Keys
var SymKeys []byte
var ProgramCert []byte

func main() {
	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort

	hostDomain, err := tao.LoadDomain(*hostcfg, nil)
	if err != nil {
		return
	}
	DerPolicyCert = nil
	if hostDomain.Keys.Cert != nil {
		DerPolicyCert = hostDomain.Keys.Cert.Raw
	}
	if DerPolicyCert == nil {
		fmt.Printf("can't retrieve policy cert\n")
		return
	}

	e := auth.PrinExt{Name: "fileclient_version_1"}
	err = tao.Parent().ExtendTaoName(auth.SubPrin{e})
	if err != nil {
		return
	}

	myTaoName, err := tao.Parent().GetTaoName()
	if err != nil {
		return
	}
	fmt.Printf("fileclient: my name is %s\n", myTaoName)

	sealedSymmetricKey, sealedSigningKey, derCert, delegation, err := fileproxy.GetMyCryptoMaterial(*fileclientPath)
	if sealedSymmetricKey == nil || sealedSigningKey == nil || delegation == nil || derCert == nil {
		fmt.Printf("fileclient: No key material present\n")
	}
	ProgramCert = derCert
	fmt.Printf("Finished fileproxy.GetMyCryptoMaterial\n")

	defer fileproxy.ZeroBytes(SymKeys)
	if sealedSymmetricKey != nil {
		symkeys, policy, err := tao.Parent().Unseal(sealedSymmetricKey)
		if err != nil {
			return
		}
		if policy != tao.SealPolicyDefault {
			fmt.Printf("fileclient: unexpected policy on unseal\n")
		}
		SymKeys = symkeys
		fmt.Printf("fileclient: Unsealed symKeys: % x\n", SymKeys)
	} else {
		symkeys, err := fileproxy.InitializeSealedSymmetricKeys(*fileclientPath, tao.Parent(), 64)
		if err != nil {
			fmt.Printf("fileclient: InitializeSealedSymmetricKeys error: %s\n", err)
		}
		SymKeys = symkeys
		fmt.Printf("fileclient: InitilizedsymKeys: % x\n", SymKeys)
	}

	if sealedSigningKey != nil {
		signingkey, err := fileproxy.SigningKeyFromBlob(tao.Parent(),
			sealedSigningKey, derCert, delegation)
		if err != nil {
			fmt.Printf("fileclient: SigningKeyFromBlob error: %s\n", err)
		}
		SigningKey = *signingkey
		fmt.Printf("fileclient: Retrieved Signing key: % x\n", SigningKey)
	} else {
		signingkey, err := fileproxy.InitializeSealedSigningKey(*fileclientPath,
			tao.Parent(), *hostDomain)
		if err != nil {
			fmt.Printf("fileclient: InitializeSealedSigningKey error: %s\n", err)
		}
		SigningKey = *signingkey
		fmt.Printf("fileclient: Initilized signingKey: % x\n", SigningKey)
	}

	policyCert, err := x509.ParseCertificate(DerPolicyCert)
	if err != nil {
		fmt.Printf("fileclient:cant ParseCertificate\n")
		return
	}
	pool := x509.NewCertPool()
	pool.AddCert(policyCert)

	tlsc, err := taonet.EncodeTLSCert(&SigningKey)
	if err != nil {
		fmt.Printf("fileserver, encode error: ", err)
		fmt.Printf("\n")
		return
	}
	conn, err := tls.Dial("tcp", serverAddr, &tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: false, // true,
	})
	if err != nil {
		fmt.Printf("fileclient:cant establish channel\n", err)
		fmt.Printf("\n")
		return
	}
	ms := util.NewMessageStream(conn)
	fmt.Printf("fileclient: Established channel\n")

	// authenticate user principal(s)
	userCert, err := ioutil.ReadFile(*fileclientPath + *fileclientKeyPath + "cert")
	if err != nil {
		fmt.Printf("fileclient: cant read cert %s\n", *fileclientPath+*fileclientKeyPath+"cert")
		return
	}
	fmt.Printf("fileclient: read cert\n")
	if userCert == nil {
		fmt.Printf("fileclient: nil user cert\n")
	}
	pks, err := ioutil.ReadFile(*fileclientPath + *fileclientKeyPath + "keys")
	if err != nil {
		fmt.Printf("fileclient: cant read key blob\n")
		return
	}
	if pks == nil {
		fmt.Printf("fileclient: nil pks\n")
	}
	fmt.Printf("fileclient: read key blob\n")
	var cks tao.CryptoKeyset
	err = proto.Unmarshal(pks, &cks)
	if err != nil {
		fmt.Printf("fileclient: cant proto unmarshal key set\n")
		return
	}
	if pks == nil {
		fmt.Printf("fileclient: cant proto unmarshaled is nil \n")
		return
	}
	fmt.Printf("fileclient: unmarshaled proto key\n")
	userKey, err := tao.UnmarshalKeyset(&cks)
	if err != nil {
		fmt.Printf("fileclient: cant unmarshal key set\n")
		return
	}
	fmt.Printf("fileclient: unmarshaled key\n")
	fmt.Printf("user key: ", userKey)
	fmt.Printf("\n")
	ok := fileproxy.AuthenticatePrincipalRequest(ms, userKey, userCert)
	if !ok {
		fmt.Printf("fileclient: cant authenticate principal\n")
		return
	}
	fmt.Printf("AuthenticatedPrincipalRequest\n")

	// create a file
	sentFileName := *testFile
	fmt.Printf("fileclient, Creating: %s\n", sentFileName)
	err = fileproxy.SendCreateFile(ms, userCert, sentFileName)
	if err != nil {
		fmt.Printf("fileclient: cant create file\n")
		return
	}
	// return: status, message, size, error
	status, message, size, err := fileproxy.GetResponse(ms)
	if err != nil {
		fmt.Printf("Error in response to SendCreate\n")
		return
	}
	fmt.Printf("Response to SendCreate\n")
	fileproxy.PrintResponse(status, message, size)
	if *status != "succeeded" {
		return
	}

	// Send File
	fmt.Printf("\nfileclient sending file %s\n", sentFileName)
	err = fileproxy.SendSendFile(ms, userCert, sentFileName)
	if err != nil {
		fmt.Printf("fileclient: SendSendFile has error\n")
		return
	}

	status, message, size, err = fileproxy.GetResponse(ms)
	if err != nil {
		fmt.Printf("Error in response to SendSend\n")
		return
	}
	fmt.Printf("Response to SendSend\n")
	fileproxy.PrintResponse(status, message, size)
	if *status != "succeeded" {
		return
	}

	err = fileproxy.SendFile(ms, *fileclientFilePath, sentFileName, nil)
	if err != nil {
		fmt.Printf("Error in response to SendFile ", err)
		fmt.Printf("\n")
		return
	}

	// Get file
	fmt.Printf("\nfileclient getting file %s\n", sentFileName)
	err = fileproxy.SendGetFile(ms, userCert, sentFileName)
	if err != nil {
		fmt.Printf("fileclient: SendGetFile has error\n")
		return
	}

	status, message, size, err = fileproxy.GetResponse(ms)
	if err != nil {
		fmt.Printf("Error in response to GetFile\n")
		return
	}
	fmt.Printf("Response to SendGet\n")
	fileproxy.PrintResponse(status, message, size)
	if *status != "succeeded" {
		return
	}

	err = fileproxy.GetFile(ms, *fileclientFilePath, sentFileName+".received", nil)
	if err != nil {
		fmt.Printf("fileclient: cant get file ", err)
		fmt.Printf("\n")
		return
	}
	fmt.Printf("fileclient: Done\n")
}
