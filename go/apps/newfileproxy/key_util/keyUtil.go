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
)

// Generate some user keys
var simpleCfg = flag.String("domain_config",
	"./tao.config",
	"path to tao configuration")
var keyPath = flag.String("path",
	"./FileClient",
	"path to FileClient files")
var numKeys = flag.Int("numKeys", 3, 
        "number of keys to generate")
var baseName = flag.String("baseUserName",
        "TestUser",
        "generic user name")


func main() {

	// Parse flags
	flag.Parse()
	outputFileName := path.Join(*keyPath, "serialized_user_keys")
	fmt.Printf("Make user keys, destination: %s\n", outputFileName)

	// Get policy key and cert.
	var signerPriv interface{}
	var signerCertificate *x509.Certificate

	userKeys := new(common.UserKeysMessage)

	for i := 0; i < *numKeys; i++ {
		userName := *baseName + strconv.Itoa(i)
		key, err := common.GenerateUserPublicKey(userName)
		if err != nil {
		}
		signerPriv = key //FIX
		keyData, err := common.MakeUserKeyStructute(key, userName, signerPriv, signerCertificate)
		serializedKey, err := common.SerializeUserKey(keyData)
		if err != nil {
		}
		if serializedKey == nil {
		}
		// userKeys.m.SerializedKeys = m.SerializedKeys 
	}
	serializedKeys, err := proto.Marshal(userKeys)
	if err != nil {
	}
	err = ioutil.WriteFile(outputFileName, serializedKeys, 0666)
	if err != nil {
	}
}
