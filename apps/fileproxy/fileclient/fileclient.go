// Copyright (c) 2014, Google Corporation.  All rights reserved.
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
// File: fileclient.go

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"

	"code.google.com/p/goprotobuf/proto"

	"github.com/jlmucb/cloudproxy/apps/fileproxy"
	tao "github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
	"github.com/jlmucb/cloudproxy/util"
)

var hostcfg = flag.String("../hostdomain/tao.config", "../hostdomain/tao.config", "path to host tao configuration")
var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var rollbackserverHost = flag.String("rollbackhost", "localhost", "address for rollback client/server")
var rollbackserverPort = flag.String("rollbackport", "8129", "port for client/server")
var fileclientPath = flag.String("fileclient_files/", "fileclient_files/", "fileclient directory")
var serverAddr string
var rollbackserverAddr string
var fileclientFilePath = flag.String("fileclient_files/stored_files/", "fileclient_files/stored_files/",
	"fileclient file directory")
var testFile = flag.String("originalTestFile", "originalTestFile", "test file")
var fileclientKeyPath = flag.String("usercreds/", "usercreds/", "user keys and certs")

func main() {

	var fileClientProgramObject fileproxy.ProgramPolicy
	var FileClientProgramObject *fileproxy.ProgramPolicy

	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort

	hostDomain, err := tao.LoadDomain(*hostcfg, nil)
	if err != nil {
		return
	}
	var derPolicyCert []byte
	if hostDomain.Keys.Cert != nil {
		derPolicyCert = hostDomain.Keys.Cert.Raw
	}
	if derPolicyCert == nil {
		log.Printf("fileclient: can't retrieve policy cert\n")
		return
	}

	e := auth.PrinExt{Name: "fileclient_version_1"}
	err = tao.Parent().ExtendTaoName(auth.SubPrin{e})
	if err != nil {
		return
	}

	taoName, err := tao.Parent().GetTaoName()
	if err != nil {
		log.Printf("fileserver: cant get tao name\n")
		return
	}
	log.Printf("fileclient: my name is %s\n", taoName)

	sealedSymmetricKey, sealedSigningKey, programCert, delegation, err := fileproxy.LoadProgramKeys(*fileclientPath)
	if err != nil {
		log.Printf("fileclient: cant retrieve key material\n")
	}
	if sealedSymmetricKey == nil || sealedSigningKey == nil || delegation == nil || programCert == nil {
		log.Printf("fileclient: No key material present\n")
	}
	log.Printf("Finished fileproxy.LoadProgramKeys\n")

	var symKeys []byte
	if sealedSymmetricKey != nil {
		symKeys, policy, err := tao.Parent().Unseal(sealedSymmetricKey)
		if err != nil {
			return
		}
		if policy != tao.SealPolicyDefault {
			log.Printf("fileclient: unexpected policy on unseal\n")
		}
		log.Printf("fileclient: Unsealed symKeys: % x\n", symKeys)
	} else {
		symKeys, err := fileproxy.InitializeSealedSymmetricKeys(*fileclientPath, tao.Parent(), fileproxy.SizeofSymmetricKeys)
		if err != nil {
			log.Printf("fileclient: InitializeSealedSymmetricKeys error: %s\n", err)
		}
		log.Printf("fileclient: InitilizedsymKeys: % x\n", symKeys)
	}
	defer fileproxy.ZeroBytes(symKeys)

	var signingKey *tao.Keys
	if sealedSigningKey != nil {
		signingKey, err = fileproxy.SigningKeyFromBlob(tao.Parent(),
			sealedSigningKey, programCert, delegation)
		if err != nil {
			log.Printf("fileclient: SigningKeyFromBlob error: %s\n", err)
		}
		log.Printf("fileclient: Retrieved Signing key: % x\n", *signingKey)
	} else {
		signingKey, err = fileproxy.InitializeSealedSigningKey(*fileclientPath,
			tao.Parent(), *hostDomain)
		if err != nil {
			log.Printf("fileclient: InitializeSealedSigningKey error: %s\n", err)
		}
		log.Printf("fileclient: Initilized signingKey: % x\n", *signingKey)
	}

	FileClientProgramObject = &fileClientProgramObject
	_ = FileClientProgramObject.InitProgramPolicy(derPolicyCert, taoName.String(), *signingKey, symKeys, programCert)

	policyCert, err := x509.ParseCertificate(derPolicyCert)
	if err != nil {
		log.Printf("fileclient:cant ParseCertificate\n")
		return
	}
	log.Printf("fileclient: place 0\n")
	pool := x509.NewCertPool()
	pool.AddCert(policyCert)

	tlsc, err := taonet.EncodeTLSCert(signingKey)
	if err != nil {
		log.Printf("fileclient, encode error: ", err)
		log.Printf("\n")
		return
	}
	conn, err := tls.Dial("tcp", serverAddr, &tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: false,
	})
	if err != nil {
		log.Printf("fileclient: cant establish channel\n", err)
		log.Printf("\n")
		return
	}
	ms := util.NewMessageStream(conn)
	log.Printf("fileclient: Established channel\n")

	// Authenticate user principal(s).
	userCert, err := ioutil.ReadFile(*fileclientPath + *fileclientKeyPath + "cert")
	if err != nil {
		log.Printf("fileclient: cant read cert %s\n", *fileclientPath+*fileclientKeyPath+"cert")
		return
	}
	log.Printf("fileclient: read cert\n")
	if userCert == nil {
		log.Printf("fileclient: nil user cert\n")
	}
	pks, err := ioutil.ReadFile(*fileclientPath + *fileclientKeyPath + "keys")
	if err != nil {
		log.Printf("fileclient: cant read key blob\n")
		return
	}
	if pks == nil {
		log.Printf("fileclient: nil pks\n")
	}
	log.Printf("fileclient: read key blob\n")
	var cks tao.CryptoKeyset
	err = proto.Unmarshal(pks, &cks)
	if err != nil {
		log.Printf("fileclient: cant proto unmarshal key set\n")
		return
	}
	if pks == nil {
		log.Printf("fileclient: cant proto unmarshaled is nil \n")
		return
	}
	log.Printf("fileclient: unmarshaled proto key\n")
	userKey, err := tao.UnmarshalKeyset(&cks)
	if err != nil {
		log.Printf("fileclient: cant unmarshal key set\n")
		return
	}
	log.Printf("fileclient: unmarshaled key\n")
	log.Printf("user key: ", userKey)
	log.Printf("\n")
	ok := fileproxy.AuthenticatePrincipalRequest(ms, userKey, userCert)
	if !ok {
		log.Printf("fileclient: cant authenticate principal\n")
		return
	}
	log.Printf("fileclient: AuthenticatedPrincipalRequest\n")

	// Send a rule.
	rule := "Delegate(\"jlm\", \"tom\", \"getfile\",\"myfile\")"
	log.Printf("fileclient, sending rule: %s\n", rule)
	err = fileproxy.SendRule(ms, rule, userCert)
	if err != nil {
		log.Printf("fileclient: cant create file\n")
		return
	}
	status, message, size, err := fileproxy.GetResponse(ms)
	if err != nil {
		log.Printf("fileclient: Error in response to SendCreate\n")
		return
	}
	log.Printf("Response to SendCreate\n")
	fileproxy.PrintResponse(status, message, size)
	if *status != "succeeded" {
		return
	}

	// Create a file.
	sentFileName := *testFile
	log.Printf("fileclient, Creating: %s\n", sentFileName)
	err = fileproxy.SendCreateFile(ms, userCert, sentFileName)
	if err != nil {
		log.Printf("fileclient: cant create file\n")
		return
	}
	status, message, size, err = fileproxy.GetResponse(ms)
	if err != nil {
		log.Printf("fileclient: Error in response to SendCreate\n")
		return
	}
	log.Printf("fileclient: Response to SendCreate\n")
	fileproxy.PrintResponse(status, message, size)
	if *status != "succeeded" {
		return
	}

	// Send File.
	log.Printf("\nfileclient sending file %s\n", sentFileName)
	err = fileproxy.SendSendFile(ms, userCert, sentFileName)
	if err != nil {
		log.Printf("fileclient: SendSendFile has error\n")
		return
	}

	status, message, size, err = fileproxy.GetResponse(ms)
	if err != nil {
		log.Printf("fileclient: Error in response to SendSend\n")
		return
	}
	log.Printf("fileclient: Response to SendSend\n")
	fileproxy.PrintResponse(status, message, size)
	if *status != "succeeded" {
		return
	}

	err = fileproxy.SendFile(ms, *fileclientFilePath, sentFileName, nil)
	if err != nil {
		log.Printf("fileclient: Error in response to SendFile ", err)
		log.Printf("\n")
		return
	}

	// Get file
	log.Printf("\nfileclient getting file %s\n", sentFileName)
	err = fileproxy.SendGetFile(ms, userCert, sentFileName)
	if err != nil {
		log.Printf("fileclient: SendGetFile has error\n")
		return
	}

	status, message, size, err = fileproxy.GetResponse(ms)
	if err != nil {
		log.Printf("fileclient: Error in response to GetFile\n")
		return
	}
	log.Printf("fileclient: Response to SendGet\n")
	fileproxy.PrintResponse(status, message, size)
	if *status != "succeeded" {
		return
	}

	err = fileproxy.GetFile(ms, *fileclientFilePath, sentFileName+".received", nil)
	if err != nil {
		log.Printf("fileclient: cant get file ", err)
		log.Printf("\n")
		return
	}

	// rollback test
	rollbackserverAddr = *serverHost + ":" + *rollbackserverPort
	rbconn, err := tls.Dial("tcp", rollbackserverAddr, &tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: false,
	})
	if err != nil {
		log.Printf("fileclient: cant establish rollback channel\n", err)
		log.Printf("\n")
		return
	}
	newms := util.NewMessageStream(rbconn)
	if newms == nil {
		log.Printf("cant get newms\n")
	}
	log.Printf("fileclient: Established rollback channel\n")
	// set hash
	hash := make([]byte, 128)
	for i := 0; i < 32; i++ {
		hash[i] = byte(i)
	}
	clientProgramName := taoName.String()
	ok2 := fileproxy.ClientSetResourceHashRequest(newms, clientProgramName, "test_resource", []byte(hash))
	if !ok2 {
		log.Printf("fileclient: fileproxy.ClientSetResourceHashRequest failed")
		return
	}
	log.Printf("fileclient: set fileproxy.ClientSetResourceHashRequest\n")
	// set counter
	fileproxy.ClientSetRollbackCounter(newms, int64(10))
	log.Printf("fileclient: set fileproxy.ClientSetRollbackCounter\n")
	// get counter
	ok2, counter := fileproxy.ClientGetRollbackCounter(newms, clientProgramName)
	if !ok2 {
		log.Printf("fileclient: fileproxy.ClientGetRollbackCounter failed")
		return
	}
	log.Printf("counter is %d\n", counter)
	// get verify
	ok2, newhash := fileproxy.ClientGetRollbackHashedVerifierRequest(newms, clientProgramName, "test_resource")
	if !ok2 {
		log.Printf("fileclient: fileproxy.ClientGetRollbackHashedVerifierRequest failed")
		return
	}
	log.Printf("fileclient: newhash is %x\n", newhash)

	log.Printf("fileclient: Done\n")
}
