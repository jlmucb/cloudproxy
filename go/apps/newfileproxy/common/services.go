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
// File: services.go

package common;

import (
	// "crypto/rand"
	// "crypto/x509"
	//"errors"
	// "fmt"
	// "io/ioutil"
	// "os"
	// "path"

	// "github.com/jlmucb/cloudproxy/go/tao"
	// "github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/apps/simpleexample/taosupport"
	"github.com/jlmucb/cloudproxy/go/apps/newfileproxy/resourcemanager"
)

// SendFile reads a file from disk and streams it to a receiver across a
// MessageStream. 
func SendFile(ms *util.MessageStream, dir string, filename string, keys []byte) error {
	// Read file from disk
	// out, err := ioutil.ReadFile(filename)
	// Unprotect it
	// taosupport.Unprotect(keys []byte, in []byte) ([]byte, error)
	// Write file bytes to channel
	// SendMessage
	return nil
}

// GetFile receives bytes from a sender and optionally encrypts them and adds
// integrity protection, and writes them to disk.
func GetFile(ms *util.MessageStream, dir string, filename string, keys []byte) error {
	// Read bytes from channel
	// outerMessage, nil := taosupport.GetMessage(ms)
	// Right response? No errors?
	// Unmarshal
	// Protect them with keys
	// taosupport.Protect(keys []byte, in []byte) ([]byte, error)
	// Write them to disk (doesn't support large files for now)
	// err := ioutil.WriteFile(filename, fileContents, 0644)
	return nil
}

type AuthentictedPrincipals struct {
	ValidPrincipals []resourcemanager.PrincipalInfo
};

func FailureResponse() *taosupport.SimpleMessage {
	return nil
}

func SuccessResponse() *taosupport.SimpleMessage {
	return nil
}

func IsAuthorized(action MessageType, resourceInfo *resourcemanager.ResourceInfo,
		policyKey []byte, principals* AuthentictedPrincipals) bool {
	return false
}

func RequestChallenge(ms *util.MessageStream, cert []byte) error {
	return nil
}

func Create(ms *util.MessageStream, name string, cert []byte) error {
	return nil
}

func Delete(ms *util.MessageStream, name string) error {
	return nil
}

func AddOwner(ms *util.MessageStream, certs [][]byte) error {
	return nil
}

func AddReader(ms *util.MessageStream, certs [][]byte) error {
	return nil
}

func AddWriter(ms *util.MessageStream, certs [][]byte, nonce []byte) error {
	return nil
}

func DeleteOwner(ms *util.MessageStream, certs [][]byte) error {
	return nil
}

func DeleteReader(ms *util.MessageStream, certs [][]byte) error {
	return nil
}

func DeleteWriter(ms *util.MessageStream, certs [][]byte) error {
	return nil
}

func ReadResource(ms *util.MessageStream, resourceName string) error {
	return nil
}

func WriteResource(ms *util.MessageStream, resourceName string) error {
	return nil
}

func DoVerifyChallenge(ms *util.MessageStream, policyKey []byte, resourceMaster *resourcemanager.ResourceMasterInfo,
		principals *AuthentictedPrincipals, msg FileproxyMessage) bool {
	return false
}

// This is actually done by the server.
func DoChallenge(ms *util.MessageStream, policyKey []byte, resourceMaster *resourcemanager.ResourceMasterInfo,
                principals *AuthentictedPrincipals, msg FileproxyMessage) error {
	// Construct challenge
	// Send it
	// Get response
	// Should be a VERIFY_CHALLENGE response
	// If it verifies, put on authenticated principals
	// Send response
	return nil
}

func DoCreate(ms *util.MessageStream, policyKey []byte, resourceMaster *resourcemanager.ResourceMasterInfo,
                principals* AuthentictedPrincipals, msg FileproxyMessage) {
	// Authorized?
	// Put it in table.
	// Send response
	return
}

func DoDelete(ms *util.MessageStream, policyKey []byte, resourceMaster *resourcemanager.ResourceMasterInfo,
                principals* AuthentictedPrincipals, msg FileproxyMessage) {
	// Authorized?
	// Remove it from table.
	// Send response
	return
}

func DoAddOwner(ms *util.MessageStream, policyKey []byte, resourceMaster *resourcemanager.ResourceMasterInfo,
                principals* AuthentictedPrincipals, msg FileproxyMessage) {
	// Authorized?
	// Add it
	// Send response
	return
}

func DoAddReader(ms *util.MessageStream, policyKey []byte, resourceMaster *resourcemanager.ResourceMasterInfo,
                principals* AuthentictedPrincipals, msg FileproxyMessage) {
	return
}

func DoAddWriter(ms *util.MessageStream, policyKey []byte, resourceMaster *resourcemanager.ResourceMasterInfo,
                principals* AuthentictedPrincipals, msg FileproxyMessage) {
	return
}

func DoDeleteOwner(ms *util.MessageStream, policyKey []byte, resourceMaster *resourcemanager.ResourceMasterInfo,
                principals* AuthentictedPrincipals, msg FileproxyMessage) {
	return
}

func DoDeleteReader(ms *util.MessageStream, policyKey []byte, resourceMaster *resourcemanager.ResourceMasterInfo,
                principals* AuthentictedPrincipals, msg FileproxyMessage) {
	return
}

func DoDeleteWriter(ms *util.MessageStream, policyKey []byte, resourceMaster *resourcemanager.ResourceMasterInfo,
                principals* AuthentictedPrincipals, msg FileproxyMessage) {
	return
}

func DoReadResource(ms *util.MessageStream, policyKey []byte, resourceMaster *resourcemanager.ResourceMasterInfo,
                principals* AuthentictedPrincipals, msg FileproxyMessage) {
	// In table?
	// Authorized?
	// Read and decrypt file
	return
}

func DoWriteResource(ms *util.MessageStream, policyKey []byte, resourceMaster *resourcemanager.ResourceMasterInfo,
                principals* AuthentictedPrincipals, msg FileproxyMessage) {
	// In table?
	// Authorized?
	// Encrypt and write file
	return
}

// Dispatch

func DoRequest(ms *util.MessageStream, policyKey []byte,
		resourceMaster *resourcemanager.ResourceMasterInfo,
		principals* AuthentictedPrincipals, req []byte) {
	msg := new(FileproxyMessage);
	err := proto.Unmarshal(req, msg)
	if err != nil {
		return
	}
	switch(*msg.Type) {
	default:
		resp := new(taosupport.SimpleMessage)
		mt := int32(taosupport.MessageType_RESPONSE)
		resp.MessageType = &mt
		errString := "Unsupported request"
		resp.Err = &errString
		taosupport.SendMessage(ms, resp)
		return
	case MessageType_REQUEST_CHALLENGE:
		DoChallenge(ms, policyKey, resourceMaster, principals, *msg)
		return
	case MessageType_CREATE:
		DoCreate(ms, policyKey, resourceMaster, principals, *msg)
		return
	case MessageType_DELETE:
		DoDelete(ms, policyKey, resourceMaster, principals, *msg)
		return
	case MessageType_ADDREADER:
		DoAddReader(ms, policyKey, resourceMaster, principals, *msg)
		return
	case MessageType_ADDOWNER:
		DoAddOwner(ms, policyKey, resourceMaster, principals, *msg)
		return
	case MessageType_ADDWRITER:
		DoAddWriter(ms, policyKey, resourceMaster, principals, *msg)
		return
	case MessageType_DELETEREADER:
		DoDeleteReader(ms, policyKey, resourceMaster, principals, *msg)
		return
	case MessageType_DELETEOWNER:
		DoDeleteOwner(ms, policyKey, resourceMaster, principals, *msg)
		return
	case MessageType_DELETEWRITER:
		DoDeleteWriter(ms, policyKey, resourceMaster, principals, *msg)
		return
	case MessageType_READ:
		DoReadResource(ms, policyKey, resourceMaster, principals, *msg)
		return
	case MessageType_WRITE:
		DoWriteResource(ms, policyKey, resourceMaster, principals, *msg)
		return
	}
}

