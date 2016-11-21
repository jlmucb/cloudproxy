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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path"
	"sync"
	"time"

	// "github.com/jlmucb/cloudproxy/go/tao"
	// "github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/apps/simpleexample/taosupport"
	"github.com/jlmucb/cloudproxy/go/apps/newfileproxy/resourcemanager"
)

type AuthentictedPrincipals struct {
	ValidPrincipals []resourcemanager.CombinedPrincipal
}

type KeyData struct {
	Cert []byte
	Certificate *x509.Certificate
	Key *ecdsa.PrivateKey
}

type ServerData struct {
	PolicyCert	*x509.Certificate
	PrincipalsMutex sync.RWMutex
	Principals AuthentictedPrincipals
	PesourceMutex  sync.RWMutex
	ResourceManager *resourcemanager.ResourceMasterInfo
}

type ClientData struct {
	PolicyCert	*x509.Certificate
	UserMutex	sync.RWMutex
	Userkeys	[]KeyData
}

func stringIntoPointer(s1 string) *string {
        return &s1
}

func intIntoPointer(i int) *int32 {
	ii := int32(i)
        return &ii
}

// SendFile reads a file from disk and streams it to a receiver across a
// MessageStream. 
func SendFile(ms *util.MessageStream, serverData *ServerData,
		info *resourcemanager.ResourceInfo) error {
	fileContents, err := info.Read(*serverData.ResourceManager.BaseDirectoryName)
	if err != nil {
		return errors.New("No message payload")
	}
	fmt.Printf("File contents: %x\n", fileContents)
	var outerMessage taosupport.SimpleMessage
	outerMessage.MessageType = intIntoPointer(int(taosupport.MessageType_RESPONSE))
	var msg FileproxyMessage
	msgtype := MessageType(MessageType_READ)
	msg.Type = &msgtype
	msg.NumTotalBuffers = intIntoPointer(1)
	msg.CurrentBuffer = intIntoPointer(1)
	msg.Data[0] = fileContents
	var payload []byte
	payload, err = proto.Marshal(&msg)
	outerMessage.Data[0] = payload
	return taosupport.SendMessage(ms, &outerMessage)
}

// GetFile receives bytes from a sender and optionally encrypts them and adds
// integrity protection, and writes them to disk.
func GetFile(ms *util.MessageStream, serverData *ServerData, 
		info *resourcemanager.ResourceInfo) error {
	// Read bytes from channel
	outerMessage, err := taosupport.GetMessage(ms)
	if err != nil {
		return errors.New("Bad message")
	}
	if *outerMessage.MessageType != *intIntoPointer(int(taosupport.MessageType_RESPONSE)) {
		return errors.New("Bad message")
	}
	if len(outerMessage.Data) == 0 {
		return errors.New("No message payload")
	}
	var msg FileproxyMessage
	err = proto.Unmarshal(outerMessage.Data[0], &msg)
	if err != nil {
		return errors.New("Bad payload message")
	}
	if msg.Type == nil || *msg.Type != MessageType_READ {
		return errors.New("Wrong message response")
	}
	if len(msg.Data[0]) == 0 {
		return errors.New("No file contents")
	}
	fileContents := msg.Data[0]
	return info.Write(*serverData.ResourceManager.BaseDirectoryName, fileContents)
}

func FailureResponse(ms *util.MessageStream, msgType int, err_string string) {
	var outerMessage taosupport.SimpleMessage
	outerMessage.MessageType = intIntoPointer(msgType)
	outerMessage.Err = stringIntoPointer(err_string)
	taosupport.SendMessage(ms, &outerMessage)
	return
}

func SuccessResponse(ms *util.MessageStream, msgType int) {
	var outerMessage taosupport.SimpleMessage
	outerMessage.MessageType = intIntoPointer(msgType)
	outerMessage.Err = stringIntoPointer("success")
	taosupport.SendMessage(ms, &outerMessage)
	return
}

func IsAuthorized(action MessageType, serverData *ServerData,
		resourceInfo *resourcemanager.ResourceInfo) bool {
	switch(action) {
	default:
		return false
	case MessageType_REQUEST_CHALLENGE:
		return false
	case MessageType_CREATE:
		return false
	case MessageType_DELETE, MessageType_ADDWRITER, MessageType_DELETEWRITER, MessageType_WRITE:
		for p := range serverData.Principals.ValidPrincipals {
			if resourceInfo.IsOwner(serverData.Principals.ValidPrincipals[p]) ||
					resourceInfo.IsWriter(serverData.Principals.ValidPrincipals[p]) {
				return true
			}
		}
		return false
	case MessageType_ADDREADER, MessageType_DELETEREADER, MessageType_READ:
		for p := range serverData.Principals.ValidPrincipals {
			if resourceInfo.IsOwner(serverData.Principals.ValidPrincipals[p]) ||
					resourceInfo.IsReader(serverData.Principals.ValidPrincipals[p]) {
				return true
			}
		}
		return false
	case MessageType_ADDOWNER, MessageType_DELETEOWNER:
		for p := range serverData.Principals.ValidPrincipals {
			if resourceInfo.IsOwner(serverData.Principals.ValidPrincipals[p]) {
				return true
			}
		}
		return false
	}
}

func RequestChallenge(ms *util.MessageStream, key KeyData) error {
	var outerMessage taosupport.SimpleMessage
	outerMessage.MessageType = intIntoPointer(int(taosupport.MessageType_REQUEST))
	var msg FileproxyMessage
	msgType := MessageType_REQUEST_CHALLENGE
	msg.Type = &msgType
	msg.Data[0] = key.Cert
	var payload []byte
	payload, err := proto.Marshal(&msg)
	if err != nil {
		return err
	}
	outerMessage.Data[0] = payload
	err = taosupport.SendMessage(ms, &outerMessage)
	// Get response
	responseOuter, err := taosupport.GetMessage(ms)
	if err != nil {
		return err
	}
	if responseOuter.Err != nil && *responseOuter.Err != "success" {
		return errors.New("RequestChallenge failed")
	}
	outerChallengeMessage, err := taosupport.GetMessage(ms)
	if err != nil {
		return err
	}
	// Error?
	var challengeMessage FileproxyMessage
	err = proto.Unmarshal(outerChallengeMessage.Data[0], &challengeMessage);
	if err != nil {
	}
	nonce := challengeMessage.Data[0]
	if nonce == nil {
		return errors.New("No nonce in server response")
	}

	// Sign Nonce and send it back
	var nonceOuterMessage taosupport.SimpleMessage
	var nonceInnerMessage FileproxyMessage
	nonceInnerMessage.Type = &msgType
	signedNonce := []byte{0,1,2}
	// r, s, err := ecdsa.Sign(rand.Reader, priv *PrivateKey, nonce)
	nonceInnerMessage.Data[0] = signedNonce
	payload, err = proto.Marshal(&msg)
	if err != nil {
		return err
	}
	nonceOuterMessage.Data[0] = payload
	err = taosupport.SendMessage(ms, &nonceOuterMessage)

	// Success?
	completionMessage, err := taosupport.GetMessage(ms)
	if err != nil || (completionMessage.Err != nil && *completionMessage.Err != "success") {
		return errors.New("Verify failed")
	}
	return nil
}

func Create(ms *util.MessageStream, name string, resourceType resourcemanager.ResourceType, cert []byte) error {
	var outerMessage taosupport.SimpleMessage
	outerMessage.MessageType = intIntoPointer(int(taosupport.MessageType_REQUEST))
	var msg FileproxyMessage
	msgType := MessageType_CREATE
	msg.Type = &msgType
	msg.Arguments[0] = name
	msg.Data[0] = cert
	var payload []byte;
	payload, err := proto.Marshal(&msg)
	if err != nil {
		return err
	}
	outerMessage.Data[0] = payload
	err = taosupport.SendMessage(ms, &outerMessage)
	if err != nil {
		return err
	}
	responseOuter, err := taosupport.GetMessage(ms)
	if responseOuter.Err != nil && *responseOuter.Err != "success" {
		return errors.New("RequestChallenge failed")
	}
	return nil
}

func Delete(ms *util.MessageStream, name string) error {
	var outerMessage taosupport.SimpleMessage
	outerMessage.MessageType = intIntoPointer(int(taosupport.MessageType_REQUEST))
	var msg FileproxyMessage
	msgType := MessageType_DELETE
	msg.Type = &msgType
	msg.Arguments[0] = name
	payload, err := proto.Marshal(&msg)
	if err != nil {
		return err
	}
	outerMessage.Data[0] = payload
	err = taosupport.SendMessage(ms, &outerMessage)
	if err != nil {
		return err
	}
	responseOuter, err := taosupport.GetMessage(ms)
	if responseOuter.Err != nil && *responseOuter.Err != "success" {
		return errors.New("RequestChallenge failed")
	}
	return nil
}

func AddDelete(ms *util.MessageStream, msgType MessageType, resourceName string, certs [][]byte) error {
	var outerMessage taosupport.SimpleMessage
	outerMessage.MessageType = intIntoPointer(int(taosupport.MessageType_REQUEST))
	var msg FileproxyMessage
	msg.Type = &msgType
	msg.Arguments[0] = resourceName
	for i := 0; i < len(certs); i++ {
		msg.Data[i] = certs[i]
	}
	var payload []byte;
	payload, err := proto.Marshal(&msg)
	if err != nil {
		return err
	}
	outerMessage.Data[0] = payload
	err = taosupport.SendMessage(ms, &outerMessage)
	if err != nil {
		return err
	}
	responseOuter, err := taosupport.GetMessage(ms)
	if responseOuter.Err != nil && *responseOuter.Err != "success" {
		return errors.New("RequestChallenge failed")
	}
	return nil
}

func AddOwner(ms *util.MessageStream, resourceName string, certs [][]byte) error {
	return AddDelete(ms, MessageType_ADDOWNER, resourceName, certs)
}

func AddReader(ms *util.MessageStream, resourceName string, certs [][]byte) error {
	return AddDelete(ms, MessageType_ADDREADER, resourceName, certs)
}

func AddWriter(ms *util.MessageStream, resourceName string, certs [][]byte) error {
	return AddDelete(ms, MessageType_ADDWRITER, resourceName, certs)
}

func DeleteOwner(ms *util.MessageStream, resourceName string, certs [][]byte) error {
	return AddDelete(ms, MessageType_DELETEOWNER, resourceName, certs)
}

func DeleteReader(ms *util.MessageStream, resourceName string, certs [][]byte) error {
	return AddDelete(ms, MessageType_DELETEREADER, resourceName, certs)
}

func DeleteWriter(ms *util.MessageStream, resourceName string, certs [][]byte) error {
	return AddDelete(ms, MessageType_DELETEWRITER, resourceName, certs)
}

func ReadResource(ms *util.MessageStream, resourceName string) ([]byte, error) {
	var outerMessage taosupport.SimpleMessage
	outerMessage.MessageType = intIntoPointer(int(taosupport.MessageType_REQUEST))
	var msg FileproxyMessage
	msgType := MessageType_READ
	msg.Type = &msgType
	msg.Arguments[0] = resourceName
	payload, err := proto.Marshal(&msg)
	if err != nil {
		return nil, err
	}
	outerMessage.Data[0] = payload
	err = taosupport.SendMessage(ms, &outerMessage)
	if err != nil {
		return nil, err
	}
	responseOuter, err := taosupport.GetMessage(ms)
	if responseOuter.Err != nil && *responseOuter.Err != "success" {
		return nil, errors.New("RequestChallenge failed")
	}
	// Response should have fileContents
	var respMsg FileproxyMessage
	err = proto.Unmarshal(responseOuter.Data[0], &respMsg)
	if err != nil {
		return nil, errors.New("Bad payload message")
	}
	if respMsg.Type == nil || *respMsg.Type != MessageType_READ {
		return nil, errors.New("Wrong message response")
	}
	if len(respMsg.Data[0]) == 0 {
		return nil, errors.New("No file contents")
	}
	fileContents := respMsg.Data[0]
	return fileContents, nil
}

func WriteResource(ms *util.MessageStream, resourceName string, fileContents []byte) error {
	var outerMessage taosupport.SimpleMessage
	outerMessage.MessageType = intIntoPointer(int(taosupport.MessageType_REQUEST))
	var msg FileproxyMessage
	msgType := MessageType_READ
	msg.Type = &msgType
	msg.Arguments[0] = resourceName
	msg.Data[0] = fileContents
	payload, err := proto.Marshal(&msg)
	if err != nil {
		return err
	}
	outerMessage.Data[0] = payload
	err = taosupport.SendMessage(ms, &outerMessage)
	if err != nil {
		return err
	}
	responseOuter, err := taosupport.GetMessage(ms)
	if responseOuter.Err != nil && *responseOuter.Err != "success" {
		return errors.New("RequestChallenge failed")
	}
	return nil
}

// This is actually done by the server.
func DoChallenge(ms *util.MessageStream, serverData *ServerData, msg FileproxyMessage) error {
	var outerMessage taosupport.SimpleMessage
	outerMessage.MessageType = intIntoPointer(int(taosupport.MessageType_RESPONSE))
	var respMsg FileproxyMessage
	msgType := MessageType_CHALLENGE
	respMsg.Type = &msgType
	var nonce [32]byte
	n, err := rand.Read(nonce[:])
	if err != nil || n < 32 {
		return errors.New("RequestChallenge can't generate nonce")
	}
	respMsg.Data[0] = nonce[:]
	payload, err := proto.Marshal(&respMsg)
	if err != nil {
		return err
	}
	outerMessage.Data[0] = payload
	err = taosupport.SendMessage(ms, &outerMessage)
	if err != nil {
		return err
	}
	responseOuter, err := taosupport.GetMessage(ms)
	if responseOuter.Err != nil && *responseOuter.Err != "success" {
		return errors.New("RequestChallenge failed")
	}
	var responseMsg FileproxyMessage
	err = proto.Unmarshal(responseOuter.Data[0], &responseMsg)
	if err != nil {
		return errors.New("Bad payload message")
	}
	if responseMsg.Type == nil || *responseMsg.Type != MessageType_CHALLENGE{
		return errors.New("Wrong message response")
	}
	if len(respMsg.Data[0]) == 0 {
		return errors.New("No file contents")
	}
	signedMessage := respMsg.Data[0]
	if signedMessage == nil {
	}
	// Verify signature
	verified := bool(true)
	if verified {
		SuccessResponse(ms, int(MessageType_CHALLENGE))
	} else {
		FailureResponse(ms, int(MessageType_CHALLENGE), "verify failed")
	}
	return nil
}

func DoCreate(ms *util.MessageStream, serverData *ServerData, msg FileproxyMessage) {
	// Should have two arguments: resourceName, type
	if len(msg.Arguments) < 2 {
		FailureResponse(ms, int(MessageType_CREATE), "resource type not specified")
		return
	}
	resourceName := msg.Arguments[0]

	// Already there?
	info := serverData.ResourceManager.FindResource(resourceName)
	if info != nil {
		FailureResponse(ms, int(MessageType_CREATE), "resource exists")
		return
	}

	// Create ResourceInfo
	info = new(resourcemanager.ResourceInfo)
	info.Name = &msg.Arguments[0]
	encodedTime, err := resourcemanager.EncodeTime(time.Now())
	if err != nil {
	}
	info.DateCreated = &encodedTime
	info.DateModified = &encodedTime
	size := int32(0)
	info.Size = &size

	p := new(resourcemanager.PrincipalInfo)

	// Parse cert to get principal name.
	p.Cert = msg.Data[0]
	certificate, err := x509.ParseCertificate(p.Cert)
	if err != nil {
	}
	p.Name = &certificate.Subject.CommonName
	cp := resourcemanager.MakeCombinedPrincipalFromOne(p)
	err = info.AddOwner(*cp)
	if err != nil {
	}

	// Authorized?
	if !IsAuthorized(*msg.Type, serverData, info) {
		FailureResponse(ms, int(MessageType_CREATE), "not authorized")
		return
	}

	// If it's a directory, create it.
	if msg.Arguments[1] == "directory" {
		rType := int32(resourcemanager.ResourceType_DIRECTORY)
		info.Type = &rType
		fileName := path.Join(*serverData.ResourceManager.BaseDirectoryName, resourceName)
		os.Mkdir(fileName, 0666)
	} else {
		rType := int32(resourcemanager.ResourceType_DIRECTORY)
		info.Type = &rType
	}

	// Put new resource in table.
	err = serverData.ResourceManager.InsertResource(info)

	// Send response
	if err == nil {
		SuccessResponse(ms, int(MessageType_CREATE))
	} else {
		FailureResponse(ms, int(MessageType_CREATE), "Can't insert resource")
	}
	return
}

func DoDelete(ms *util.MessageStream, serverData *ServerData, msg FileproxyMessage) {
	resourceName := msg.Arguments[0]
	info := serverData.ResourceManager.FindResource(resourceName)
	if info == nil {
		FailureResponse(ms, int(MessageType_DELETE), "no such resource")
		return
	}
	if !IsAuthorized(*msg.Type, serverData, info) {
		FailureResponse(ms, int(MessageType_DELETE), "not authorized")
		return
	}
	serverData.ResourceManager.DeleteResource(resourceName)
	SuccessResponse(ms, int(MessageType_CREATE))
	return
}

func DoAddOwner(ms *util.MessageStream, serverData *ServerData, msg FileproxyMessage) {
	resourceName := msg.Arguments[0]
	info := serverData.ResourceManager.FindResource(resourceName)
	if info == nil {
		FailureResponse(ms, int(MessageType_ADDOWNER), "no such resource")
		return
	}
	if !IsAuthorized(*msg.Type, serverData, info) {
		FailureResponse(ms, int(MessageType_ADDOWNER), "not authorized")
		return
	}
	// info.AddOwner(p CombinedPrincipal)
	suc := bool(true)
	if suc {
		SuccessResponse(ms, int(MessageType_CREATE))
	} else {
		FailureResponse(ms, int(MessageType_CREATE), "Can't insert resource")
	}
	return
}

func DoAddReader(ms *util.MessageStream, serverData *ServerData, msg FileproxyMessage) {
	resourceName := msg.Arguments[0]
	info := serverData.ResourceManager.FindResource(resourceName)
	if info == nil {
		FailureResponse(ms, int(MessageType_ADDREADER), "no such resource")
		return
	}
	if !IsAuthorized(*msg.Type, serverData, info) {
		FailureResponse(ms, int(MessageType_ADDREADER), "not authorized")
		return
	}
	// info.AddReader(p CombinedPrincipal)
	suc := bool(true)
	if suc {
		SuccessResponse(ms, int(MessageType_CREATE))
	} else {
		FailureResponse(ms, int(MessageType_CREATE), "Can't insert resource")
	}
	return
}

func DoAddWriter(ms *util.MessageStream, serverData *ServerData, msg FileproxyMessage) {
	resourceName := msg.Arguments[0]
	info := serverData.ResourceManager.FindResource(resourceName)
	if info == nil {
		FailureResponse(ms, int(MessageType_ADDWRITER), "no such resource")
		return
	}
	if !IsAuthorized(*msg.Type, serverData, info) {
		FailureResponse(ms, int(MessageType_ADDWRITER), "not authorized")
		return
	}
	// info.AddWriter(p CombinedPrincipal)
	suc := bool(true)
	if suc {
		SuccessResponse(ms, int(MessageType_CREATE))
	} else {
		FailureResponse(ms, int(MessageType_CREATE), "Can't insert resource")
	}
	return
}

func DoDeleteOwner(ms *util.MessageStream, serverData *ServerData, msg FileproxyMessage) {
	resourceName := msg.Arguments[0]
	info := serverData.ResourceManager.FindResource(resourceName)
	if info == nil {
		FailureResponse(ms, int(MessageType_DELETEOWNER), "no such resource")
		return
	}
	if !IsAuthorized(*msg.Type, serverData, info) {
		FailureResponse(ms, int(MessageType_DELETEOWNER), "not authorized")
		return
	}
	// info.DeleteOwner(p CombinedPrincipal)
	suc := bool(true)
	if suc {
		SuccessResponse(ms, int(MessageType_CREATE))
	} else {
		FailureResponse(ms, int(MessageType_CREATE), "Can't insert resource")
	}
	return
}

func DoDeleteReader(ms *util.MessageStream, serverData *ServerData, msg FileproxyMessage) {
	resourceName := msg.Arguments[0]
	info := serverData.ResourceManager.FindResource(resourceName)
	if info == nil {
		FailureResponse(ms, int(MessageType_DELETEREADER), "no such resource")
		return
	}
	if !IsAuthorized(*msg.Type, serverData, info) {
		FailureResponse(ms, int(MessageType_DELETEREADER), "not authorized")
		return
	}
	// info.DeleteWriter(p CombinedPrincipal)
	suc := bool(true)
	if suc {
		SuccessResponse(ms, int(MessageType_CREATE))
	} else {
		FailureResponse(ms, int(MessageType_CREATE), "Can't insert resource")
	}
	return
}

func DoDeleteWriter(ms *util.MessageStream, serverData *ServerData, msg FileproxyMessage) {
	resourceName := msg.Arguments[0]
	info := serverData.ResourceManager.FindResource(resourceName)
	if info == nil {
		FailureResponse(ms, int(MessageType_DELETEWRITER), "no such resource")
		return
	}
	if !IsAuthorized(*msg.Type, serverData, info) {
		FailureResponse(ms, int(MessageType_DELETEWRITER), "not authorized")
		return
	}
	// info.DeleteWriter(p CombinedPrincipal)
	suc := bool(true)
	if suc {
		SuccessResponse(ms, int(MessageType_CREATE))
	} else {
		FailureResponse(ms, int(MessageType_CREATE), "Can't insert resource")
	}
	return
}

func DoReadResource(ms *util.MessageStream, serverData *ServerData, msg FileproxyMessage) {

	resourceName := msg.Arguments[0]
	info := serverData.ResourceManager.FindResource(resourceName)
	if info == nil {
		FailureResponse(ms, int(MessageType_READ), "no such resource")
		return
	}
	if !IsAuthorized(*msg.Type, serverData, info) {
		FailureResponse(ms, int(MessageType_READ), "not authorized")
		return
	}
	// Send file
	_ = SendFile(ms, serverData, info)
	return
}

func DoWriteResource(ms *util.MessageStream, serverData *ServerData, msg FileproxyMessage) {
	resourceName := msg.Arguments[0]
	info := serverData.ResourceManager.FindResource(resourceName)
	if info == nil {
		FailureResponse(ms, int(MessageType_WRITE), "no such resource")
		return
	}
	if !IsAuthorized(*msg.Type, serverData, info) {
		FailureResponse(ms, int(MessageType_WRITE), "not authorized")
		return
	}
	// Send file
	_ = GetFile(ms, serverData, info)
	return
}

// Dispatch

func OuterFailureMessage(ms *util.MessageStream, errStr string) {
	resp := new(taosupport.SimpleMessage)
	mt := int32(taosupport.MessageType_RESPONSE)
	resp.MessageType = &mt
	resp.Err = &errStr
	taosupport.SendMessage(ms, resp)
}

func DoRequest(ms *util.MessageStream, serverData *ServerData, req taosupport.SimpleMessage) {
	// check that req is a request and has data
	if req.MessageType == nil || *req.MessageType != int32(taosupport.MessageType_REQUEST) || len(req.Data) <1 {
		OuterFailureMessage(ms, "Malformed request")
		return
	}
	msg := new(FileproxyMessage);
	err := proto.Unmarshal(req.Data[0], msg)
	if err != nil {
		return
	}
	switch(*msg.Type) {
	default:
		OuterFailureMessage(ms, "Unsupported request")
		return
	case MessageType_REQUEST_CHALLENGE:
		DoChallenge(ms, serverData, *msg)
		return
	case MessageType_CREATE:
		DoCreate(ms, serverData, *msg)
		return
	case MessageType_DELETE:
		DoDelete(ms, serverData, *msg)
		return
	case MessageType_ADDREADER:
		DoAddReader(ms, serverData, *msg)
		return
	case MessageType_ADDOWNER:
		DoAddOwner(ms, serverData, *msg)
		return
	case MessageType_ADDWRITER:
		DoAddWriter(ms, serverData, *msg)
		return
	case MessageType_DELETEREADER:
		DoDeleteReader(ms, serverData, *msg)
		return
	case MessageType_DELETEOWNER:
		DoDeleteOwner(ms, serverData, *msg)
		return
	case MessageType_DELETEWRITER:
		DoDeleteWriter(ms, serverData, *msg)
		return
	case MessageType_READ:
		DoReadResource(ms, serverData, *msg)
		return
	case MessageType_WRITE:
		DoWriteResource(ms, serverData, *msg)
		return
	}
}

