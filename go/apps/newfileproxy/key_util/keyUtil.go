// Copyright (c) 2014, Google, Inc.,  All rights reserved.
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
// File: keyUtil.go

package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"path"
	"strconv"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/apps/newfileproxy/common"
	"github.com/jlmucb/cloudproxy/go/tao"
)

var configPath = flag.String("configPath", "/Domains/domain.simpleexample/tao.config", "The Tao domain config")
var domainPass = flag.String("password", "xxx", "The domain password")
var keyPath = flag.String("path", "./tmptest", "path to user keys files")
var numKeys = flag.Int("numKeys", 3, "number of keys to generate")
var baseName = flag.String("baseUserName", "TestUser", "generic user name")

// Generate some user keys
func main() {

	// Parse flags
	flag.Parse()
	outputFileName := path.Join(*keyPath, "serialized_user_keys")
	fmt.Printf("Make user keys, destination: %s\n", outputFileName)

	// Get policy key and cert.
	domain, err := tao.LoadDomain(*configPath, []byte(*domainPass))
        if domain == nil {
                fmt.Printf("keyUtil: no domain path - %s, pass - %s, err - %s\n",
                        *configPath, *domainPass, err)
                return
        } else if err != nil {
                fmt.Printf("keyUtil: Couldn't load the config path %s: %s\n",
                        *configPath, err)
                return
        }
        fmt.Printf("key_util: Loaded domain\n")
	policyKey := domain.Keys

	var signerPriv interface{}
	signerPriv = policyKey.SigningKey.GetSigner()
	var signerCertificate *x509.Certificate
	signerCertificate = policyKey.Cert

	userKeys := new(common.UserKeysMessage)

	for i := 0; i < *numKeys; i++ {
		userName := *baseName + strconv.Itoa(i)
		key, err := common.GenerateUserPublicKey(userName)
		if err != nil {
			fmt.Printf("Can't generate user key %d\n", i)
			return
		}
		signerPriv = key //FIX
		keyData, err := common.MakeUserKeyStructute(key, userName, signerPriv, signerCertificate)
		serializedKey, err := common.SerializeUserKey(keyData)
		if err != nil {
			fmt.Printf("Can't serialize user key %d\n", i)
			return
		}
		userCertificate, err := x509.ParseCertificate(keyData.Cert)
		if err != nil {
		}
		fmt.Printf("User cert %d:\n", i)
		fmt.Printf("%x\n\n", userCertificate)
		userKeys.SerializedKeys = append(userKeys.SerializedKeys, serializedKey)
	}
	serializedKeys, err := proto.Marshal(userKeys)
	if err != nil {
	}
	err = ioutil.WriteFile(outputFileName, serializedKeys, 0666)
	if err != nil {
		fmt.Printf("Can't write %s\n", outputFileName)
		return
	}
}
