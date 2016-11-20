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
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

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

type ServerData struct {
	policyCert	*x509.Certificate
	principalsMutex sync.RWMutex
	principals AuthentictedPrincipals
	resourceMutex  sync.RWMutex
	resourceManager *resourcemanager.ResourceMasterInfo
}

type ClientData struct {
	policyCert	*x509.Certificate
	userMutex	sync.RWMutex
	certs		[][]byte
	privateKeys	[]taosupport.PrivateKeyMessage
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
	fileContents, err := info.Read(*serverData.resourceManager.BaseDirectoryName)
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
	return info.Write(*serverData.resourceManager.BaseDirectoryName, fileContents)
}

func FailureResponse(ms *util.MessageStream, msgType int, err_string string) {
	var outerMessage taosupport.SimpleMessage
	outerMessage.MessageType = intIntoPointer(msgType)
	outerMessage.Err = stringIntoPointer(err_string)
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
		for p := range serverData.principals.ValidPrincipals {
			if resourceInfo.IsOwner(serverData.principals.ValidPrincipals[p]) ||
					resourceInfo.IsWriter(serverData.principals.ValidPrincipals[p]) {
				return true
			}
		}
		return false
	case MessageType_ADDREADER, MessageType_DELETEREADER, MessageType_READ:
		for p := range serverData.principals.ValidPrincipals {
			if resourceInfo.IsOwner(serverData.principals.ValidPrincipals[p]) ||
					resourceInfo.IsReader(serverData.principals.ValidPrincipals[p]) {
				return true
			}
		}
		return false
	case MessageType_ADDOWNER, MessageType_DELETEOWNER:
		for p := range serverData.principals.ValidPrincipals {
			if resourceInfo.IsOwner(serverData.principals.ValidPrincipals[p]) {
				return true
			}
		}
		return false
	}
}

func RequestChallenge(ms *util.MessageStream, cert []byte) error {
	var outerMessage taosupport.SimpleMessage
	outerMessage.MessageType = intIntoPointer(int(taosupport.MessageType_REQUEST))
	var msg FileproxyMessage
	msgType := MessageType_REQUEST_CHALLENGE
	msg.Type = &msgType
	msg.Data[0] = cert
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
	// Get Nonce and sign it
	// Return signed nonce
	// Success?
	return nil
}

func Create(ms *util.MessageStream, name string, cert []byte) error {
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

func AddWriter(ms *util.MessageStream, resourceName string, certs [][]byte, nonce []byte) error {
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
	// Construct challenge
	// Send it
	// Get response
	// Should be a VERIFY_CHALLENGE response
	// If it verifies, put on authenticated principals
	// Send response
	return nil
}

func DoCreate(ms *util.MessageStream, serverData *ServerData, msg FileproxyMessage) {
	resourceName := msg.Arguments[0]
	info := serverData.resourceManager.FindResource(resourceName)
	if info != nil {
		FailureResponse(ms, int(MessageType_CREATE), "resource exists")
		return
	}
	infoNew := new(resourcemanager.ResourceInfo)
	if !IsAuthorized(*msg.Type, serverData, infoNew) {
		FailureResponse(ms, int(MessageType_CREATE), "not authorized")
		return
	}
	// Send response
	//m.InsertResource(infoNew *ResourceInfo)
	return
}

func DoDelete(ms *util.MessageStream, serverData *ServerData, msg FileproxyMessage) {
	resourceName := msg.Arguments[0]
	info := serverData.resourceManager.FindResource(resourceName)
	if info == nil {
		FailureResponse(ms, int(MessageType_DELETE), "no such resource")
		return
	}
	if !IsAuthorized(*msg.Type, serverData, info) {
		FailureResponse(ms, int(MessageType_DELETE), "not authorized")
		return
	}
	serverData.resourceManager.DeleteResource(resourceName)
	return
}

func DoAddOwner(ms *util.MessageStream, serverData *ServerData, msg FileproxyMessage) {
	resourceName := msg.Arguments[0]
	info := serverData.resourceManager.FindResource(resourceName)
	if info == nil {
		FailureResponse(ms, int(MessageType_ADDOWNER), "no such resource")
		return
	}
	if !IsAuthorized(*msg.Type, serverData, info) {
		FailureResponse(ms, int(MessageType_ADDOWNER), "not authorized")
		return
	}
	// info.AddOwner(p CombinedPrincipal)
	return
}

func DoAddReader(ms *util.MessageStream, serverData *ServerData, msg FileproxyMessage) {
	resourceName := msg.Arguments[0]
	info := serverData.resourceManager.FindResource(resourceName)
	if info == nil {
		FailureResponse(ms, int(MessageType_ADDREADER), "no such resource")
		return
	}
	if !IsAuthorized(*msg.Type, serverData, info) {
		FailureResponse(ms, int(MessageType_ADDREADER), "not authorized")
		return
	}
	// info.AddOwner(p CombinedPrincipal)
	return
}

func DoAddWriter(ms *util.MessageStream, serverData *ServerData, msg FileproxyMessage) {
	resourceName := msg.Arguments[0]
	info := serverData.resourceManager.FindResource(resourceName)
	if info == nil {
		FailureResponse(ms, int(MessageType_ADDWRITER), "no such resource")
		return
	}
	if !IsAuthorized(*msg.Type, serverData, info) {
		FailureResponse(ms, int(MessageType_ADDWRITER), "not authorized")
		return
	}
	// info.AddOwner(p CombinedPrincipal)
	return
}

func DoDeleteOwner(ms *util.MessageStream, serverData *ServerData, msg FileproxyMessage) {
	resourceName := msg.Arguments[0]
	info := serverData.resourceManager.FindResource(resourceName)
	if info == nil {
		FailureResponse(ms, int(MessageType_DELETEOWNER), "no such resource")
		return
	}
	if !IsAuthorized(*msg.Type, serverData, info) {
		FailureResponse(ms, int(MessageType_DELETEOWNER), "not authorized")
		return
	}
	// info.AddOwner(p CombinedPrincipal)
	return
}

func DoDeleteReader(ms *util.MessageStream, serverData *ServerData, msg FileproxyMessage) {
	resourceName := msg.Arguments[0]
	info := serverData.resourceManager.FindResource(resourceName)
	if info == nil {
		FailureResponse(ms, int(MessageType_DELETEREADER), "no such resource")
		return
	}
	if !IsAuthorized(*msg.Type, serverData, info) {
		FailureResponse(ms, int(MessageType_DELETEREADER), "not authorized")
		return
	}
	// info.DeleteWriter(p CombinedPrincipal)
	return
}

func DoDeleteWriter(ms *util.MessageStream, serverData *ServerData, msg FileproxyMessage) {
	resourceName := msg.Arguments[0]
	info := serverData.resourceManager.FindResource(resourceName)
	if info == nil {
		FailureResponse(ms, int(MessageType_DELETEWRITER), "no such resource")
		return
	}
	if !IsAuthorized(*msg.Type, serverData, info) {
		FailureResponse(ms, int(MessageType_DELETEWRITER), "not authorized")
		return
	}
	// info.DeleteWriter(p CombinedPrincipal)
	return
}

func DoReadResource(ms *util.MessageStream, serverData *ServerData, msg FileproxyMessage) {

	resourceName := msg.Arguments[0]
	info := serverData.resourceManager.FindResource(resourceName)
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
	info := serverData.resourceManager.FindResource(resourceName)
	if info == nil {
		FailureResponse(ms, int(MessageType_WRITE), "no such resource")
		return
	}
	if !IsAuthorized(*msg.Type, serverData, info) {
		FailureResponse(ms, int(MessageType_WRITE), "not authorized")
		return
	}
	// Send file
	_ = SendFile(ms, serverData, info)
	return
}

// Dispatch

func DoRequest(ms *util.MessageStream, serverData *ServerData, req []byte) {
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

