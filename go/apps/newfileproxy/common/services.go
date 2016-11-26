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
	resourcemanager "github.com/jlmucb/cloudproxy/go/apps/newfileproxy/resourcemanager"
)

type KeyData struct {
	Cert []byte
	Certificate *x509.Certificate
	Key *ecdsa.PrivateKey
}

type ServerData struct {
	PolicyCert []byte
	PolicyCertificate *x509.Certificate
	ResourceMutex  sync.RWMutex
	ResourceManager *resourcemanager.ResourceMasterInfo
	FileSecrets []byte
}

type ServerConnectionData struct {
	PrincipalsMutex sync.RWMutex
	Principals []*resourcemanager.PrincipalInfo
}

type ClientData struct {
	PolicyCert	*x509.Certificate
	UserMutex	sync.RWMutex
	Userkeys	[]KeyData
}

func (s *ServerData) InitServerData() {
	s.ResourceManager= new(resourcemanager.ResourceMasterInfo)
}

func stringIntoPointer(s1 string) *string {
        return &s1
}

func intIntoPointer(i int) *int32 {
	ii := int32(i)
        return &ii
}

func PrintMessage(msg *FileproxyMessage) {
	/*
	 *  required MessageType Type = 1;
	 *  // For CREATE, resourcename, type ("file" or "directory")
	 *  // For DELETE, resource name
	 *  // For READ, resource name
	 *  // For WRITE, resource name
	 *  // For ADDREADER, resource name
	 *  // For ADDOWNER, resource name
	 *  // For ADDWRITER, resource name
	 *  // For DELETEREADER, resource name
	 *  // For DELETEOWNER, resource name
	 *  // For DELETEWRITER, resource name
	 */
	fmt.Printf("FileproxyMessage\n")
	if msg.TypeOfService!= nil {
		switch(*msg.TypeOfService) {
		case ServiceType_REQUEST_CHALLENGE:
			fmt.Printf("\tREQUEST_CHALLENGE message\n");
		case ServiceType_CHALLENGE_RESPONSE:
			fmt.Printf("\t_RESPONSE message\n");
		case ServiceType_SIGNED_CHALLENGE:
			fmt.Printf("\tSIGNED_CHALLENGE message\n");
		case ServiceType_CREATE:
			fmt.Printf("\tCREATE message\n");
		case ServiceType_DELETE:
			fmt.Printf("\tDELETE message\n");
		case ServiceType_ADDREADER:
			fmt.Printf("\tADD_READER message\n");
		case ServiceType_ADDOWNER:
			fmt.Printf("\tADDOWNER message\n");
		case ServiceType_ADDWRITER:
			fmt.Printf("\tADDWRITER message\n");
		case ServiceType_DELETEREADER:
			fmt.Printf("\tDELETEREADER message\n");
		case ServiceType_DELETEOWNER:
			fmt.Printf("\tDELETEOWNER message\n");
		case ServiceType_DELETEWRITER:
			fmt.Printf("\tDELETEWRITER message\n");
		case ServiceType_READ:
			fmt.Printf("\tREAD message\n");
		case ServiceType_WRITE:
			fmt.Printf("\tWRITE message\n");
		}
	}
	if msg.Err != nil {
		fmt.Printf("\tError: %s\n", *msg.Err)
	}
	fmt.Printf("\t%d Arguments:\n", len(msg.Arguments))
	for i := 0; i < len(msg.Arguments); i++ {
		fmt.Printf("\t\tArgument[%d]: %s\n", len(msg.Arguments), msg.Arguments[i])
	}
	fmt.Printf("\n")
	fmt.Printf("\t%d Data:\n", len(msg.Data))
	for i := 0; i < len(msg.Data); i++ {
		fmt.Printf("\t\tData[%d]: %x\n", len(msg.Data), msg.Data[i])
	}
	fmt.Printf("\n")
}

func SendMessage(ms *util.MessageStream, msg *FileproxyMessage) error {
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

func GetMessage(ms *util.MessageStream) (*FileproxyMessage, error) {
	resp, err := ms.ReadString()
	if err != nil {
		return nil, err
	}
	msg := new(FileproxyMessage)
	err = proto.Unmarshal([]byte(resp), msg)
	if err != nil {
		return nil, errors.New("GetResponse: Can't unmarshal message")
	}
	return msg, nil
}

func IsPrincipalOnList(principals []*resourcemanager.PrincipalInfo, principal *resourcemanager.PrincipalInfo) bool {
	for i := 0; i < len(principals); i++ {
		if principal.Name != nil && principals[i].Name != nil && principal.Name == principals[i].Name {
			return true
		}
	}
	return false
}

func IsVerifiedCombinedPrincipal(combinedPrincipal *resourcemanager.CombinedPrincipal,
		principals []*resourcemanager.PrincipalInfo) bool {

	for i := 0; i < len(combinedPrincipal.Principals); i++ {
		if !IsPrincipalOnList(principals, combinedPrincipal.Principals[i]) {
			return false;
		}
	}
	return true
}

func HasSatisfyingCombinedPrincipal(combinedPrincipals []*resourcemanager.CombinedPrincipal,
		principals []*resourcemanager.PrincipalInfo, mutex *sync.RWMutex) bool {
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}
	for i := 0; i < len(combinedPrincipals); i++ {
		if IsVerifiedCombinedPrincipal(combinedPrincipals[i], principals) {
			return true;
		}
	}
	return false
}

// SendFile reads a file from disk and streams it to a receiver across a
// MessageStream. 
func SendFile(ms *util.MessageStream, serverData *ServerData, info *resourcemanager.ResourceInfo) error {
	fileContents, err := info.Read(*serverData.ResourceManager.BaseDirectoryName)
	if err != nil {
		return errors.New("No message payload")
	}
	fmt.Printf("File contents: %x\n", fileContents)
	var msg FileproxyMessage
	serviceType := ServiceType(ServiceType_WRITE)
	msg.TypeOfService = &serviceType
	msg.Data = append(msg.Data, fileContents)
	return SendMessage(ms, &msg)
}

// GetFile receives bytes from a sender and optionally encrypts them and adds
// integrity protection, and writes them to disk.
func GetFile(ms *util.MessageStream, serverData *ServerData, 
		info *resourcemanager.ResourceInfo) error {
	msg, err := GetMessage(ms)
	if err != nil {
		return errors.New("Bad message")
	}
	if msg.TypeOfService == nil || *msg.TypeOfService != ServiceType_READ {
		return errors.New("Wrong message response")
	}
	fileContents := msg.Data[0]
	return info.Write(*serverData.ResourceManager.BaseDirectoryName, fileContents)
}

func FailureResponse(ms *util.MessageStream, serviceType ServiceType, err_string string) {
	var responseMsg FileproxyMessage
	responseMsg.TypeOfService = &serviceType
	responseMsg.Err = stringIntoPointer(err_string)
	SendMessage(ms, &responseMsg)
	return
}

func SuccessResponse(ms *util.MessageStream, serviceType ServiceType) {
	var responseMsg FileproxyMessage
	responseMsg.TypeOfService = &serviceType
	responseMsg.Err = stringIntoPointer("success")
	SendMessage(ms, &responseMsg)
	return
}

func IsAuthorized(action ServiceType, serverData *ServerData, connectionData *ServerConnectionData,
		resourceInfo *resourcemanager.ResourceInfo) bool {
	switch(action) {
	default:
		return false
	case ServiceType_REQUEST_CHALLENGE:
		return false
	case ServiceType_CREATE:
		return false
	case ServiceType_DELETE, ServiceType_ADDWRITER, ServiceType_DELETEWRITER, ServiceType_WRITE:
		return HasSatisfyingCombinedPrincipal(resourceInfo.Owners, connectionData.Principals,
					&serverData.ResourceMutex) ||
				HasSatisfyingCombinedPrincipal(resourceInfo.Writers, connectionData.Principals,
					&serverData.ResourceMutex)
	case ServiceType_ADDREADER, ServiceType_DELETEREADER, ServiceType_READ:
		return HasSatisfyingCombinedPrincipal(resourceInfo.Owners, connectionData.Principals,
					&serverData.ResourceMutex) ||
				HasSatisfyingCombinedPrincipal(resourceInfo.Readers, connectionData.Principals,
					&serverData.ResourceMutex)
			return true
		return false
	case ServiceType_ADDOWNER, ServiceType_DELETEOWNER:
		return HasSatisfyingCombinedPrincipal(resourceInfo.Owners, connectionData.Principals,
			&serverData.ResourceMutex)
	}
	return false
}

func SignNonce(nonce []byte, signKey *ecdsa.PrivateKey) ([]byte, []byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, signKey, nonce)
	if err != nil {
		return nil, nil, err
	}
	return r.Bytes(), s.Bytes(), nil
}

func RequestChallenge(ms *util.MessageStream, key KeyData) error {

	// Nonce message
	var initialRequestMsg FileproxyMessage
	serviceType := ServiceType_REQUEST_CHALLENGE
	initialRequestMsg.TypeOfService = &serviceType
	initialRequestMsg.Data = append(initialRequestMsg.Data, key.Cert)
	SendMessage(ms, &initialRequestMsg)

	// Get response
	initialResponse, err := GetMessage(ms)
	if err != nil {
fmt.Printf("RequestChallenge: bad GetMessage\n")
		return err
	}
	// Check message type and service type
	if initialResponse.Err != nil && *initialResponse.Err != "success" {
fmt.Printf("RequestChallenge: not success\n")
PrintMessage(initialResponse)
		return errors.New("RequestChallenge failed")
	}
fmt.Printf("RequestChallenge initial response\n")
PrintMessage(initialResponse);

	// Error?
	if len(initialResponse.Data) < 1 {
fmt.Printf("RequestChallenge: malformed 1\n")
		return errors.New("malformed response")
	}
	nonce := initialResponse.Data[0]

	// Sign Nonce and send it back
	var signedChallengeMessage FileproxyMessage

	s1, s2, err := SignNonce(nonce, key.Key)
	if err != nil {
fmt.Printf("RequestChallenge: SignNonce fails\n")
		return err
	}
	serviceType = ServiceType_SIGNED_CHALLENGE
	signedChallengeMessage.TypeOfService = &serviceType
	signedChallengeMessage.Data = append(signedChallengeMessage.Data, s1)
	signedChallengeMessage.Data = append(signedChallengeMessage.Data, s2)
fmt.Printf("RequestChallenge response\n")
PrintMessage(&signedChallengeMessage);

	err = SendMessage(ms, &signedChallengeMessage)
	if err != nil {
fmt.Printf("RequestChallenge: SendMessagefails\n")
		return err
	}

	// Success?
	completionMessage, err := GetMessage(ms)
	if err != nil || (completionMessage.Err != nil && *completionMessage.Err != "success") {
fmt.Printf("RequestChallenge: verify failed\n")
		return errors.New("Verify failed")
	}
	return nil
}

func Create(ms *util.MessageStream, name string, resourceType resourcemanager.ResourceType, cert []byte) error {
	var requestMessage FileproxyMessage
	serviceType := ServiceType_CREATE
	requestMessage.TypeOfService = &serviceType
	requestMessage.Arguments = append(requestMessage.Arguments, name)
	requestMessage.Data = append(requestMessage.Data, cert)
	err := SendMessage(ms, &requestMessage)
	if err != nil {
		return err
	}
	responseMessage, err := GetMessage(ms)
	if responseMessage.Err != nil && *responseMessage.Err != "success" {
		return errors.New("Create failed")
	}
	return nil
}

func Delete(ms *util.MessageStream, name string) error {
	var msg FileproxyMessage
	serviceType := ServiceType_DELETE
	msg.TypeOfService = &serviceType
	msg.Arguments = append(msg.Arguments, name)
	err := SendMessage(ms, &msg)
	if err != nil {
		return err
	}
	responseMessage, err := GetMessage(ms)
	if responseMessage.Err != nil && *responseMessage.Err != "success" {
		return errors.New("Delete failed")
	}
	return nil
}

func AddDelete(ms *util.MessageStream, serviceType ServiceType, resourceName string, certs [][]byte) error {
	var msg FileproxyMessage
	msg.TypeOfService = &serviceType
	msg.Arguments = append(msg.Arguments, resourceName)
	for i := 0; i < len(certs); i++ {
		msg.Data = append(msg.Data, certs[i])
	}
	err := SendMessage(ms, &msg)
	if err != nil {
		return err
	}
	responseMessage, err := GetMessage(ms)
	if responseMessage.Err != nil && *responseMessage.Err != "success" {
		return errors.New("AddDelete failed")
	}
	return nil
}

func AddOwner(ms *util.MessageStream, resourceName string, certs [][]byte) error {
	return AddDelete(ms, ServiceType_ADDOWNER, resourceName, certs)
}

func AddReader(ms *util.MessageStream, resourceName string, certs [][]byte) error {
	return AddDelete(ms, ServiceType_ADDREADER, resourceName, certs)
}

func AddWriter(ms *util.MessageStream, resourceName string, certs [][]byte) error {
	return AddDelete(ms, ServiceType_ADDWRITER, resourceName, certs)
}

func DeleteOwner(ms *util.MessageStream, resourceName string, certs [][]byte) error {
	return AddDelete(ms, ServiceType_DELETEOWNER, resourceName, certs)
}

func DeleteReader(ms *util.MessageStream, resourceName string, certs [][]byte) error {
	return AddDelete(ms, ServiceType_DELETEREADER, resourceName, certs)
}

func DeleteWriter(ms *util.MessageStream, resourceName string, certs [][]byte) error {
	return AddDelete(ms, ServiceType_DELETEWRITER, resourceName, certs)
}

func ReadResource(ms *util.MessageStream, resourceName string) ([]byte, error) {
	return nil, nil
}

func WriteResource(ms *util.MessageStream, resourceName string, fileContents []byte) error {
	return nil
}

// This is actually done by the server.
func DoChallenge(ms *util.MessageStream, serverData *ServerData,
		connectionData *ServerConnectionData, msg FileproxyMessage) error {
fmt.Printf("DoChallenge\n")
PrintMessage(&msg)
fmt.Printf("\n")
	if len(msg.Data) < 1 {
		FailureResponse(ms, ServiceType_REQUEST_CHALLENGE, "No cert included")
		return nil
	}
	userCert := msg.Data[0]

	userCertificate, err := x509.ParseCertificate(userCert)
	if err != nil {
		FailureResponse(ms, ServiceType_REQUEST_CHALLENGE, "Bad cert")
		return err
	}
	ok, _, err := VerifyCertificateChain(serverData.PolicyCertificate, nil, userCertificate)
	if !ok {
		FailureResponse(ms, ServiceType_REQUEST_CHALLENGE, "User Cert invalid")
		return nil
	}

	var challengeMessage FileproxyMessage
	// Generate challenge and send it.
	nonce := make([]byte, 32)
	n, err := rand.Read(nonce)
	if err != nil || n < 32 {
fmt.Printf("DoChallenge 0\n")
		FailureResponse(ms, ServiceType_REQUEST_CHALLENGE, "Can't generate challenge")
		return errors.New("RequestChallenge can't generate nonce")
	}
fmt.Printf("DoChallenge 1\n")
	challengeMessage.Data = append(challengeMessage.Data, nonce)
	challengeMessage.Err = stringIntoPointer("success")
	serviceType := ServiceType_REQUEST_CHALLENGE
	challengeMessage.TypeOfService = &serviceType
	err = SendMessage(ms, &challengeMessage)
	if err != nil {
		FailureResponse(ms, ServiceType_REQUEST_CHALLENGE, "Can't send challenge")
		return errors.New("RequestChallenge can't send challenge ")
	}

	// Signed response.
	signedResponseMsg, err := GetMessage(ms)
	if signedResponseMsg.Err != nil && *signedResponseMsg.Err != "success" {
		return errors.New("RequestChallenge failed")
	}
fmt.Printf("DoChallenge 3\n")

	// Verify signature
	s1 := signedResponseMsg.Data[0]
	s2 := signedResponseMsg.Data[1]
	if VerifyNonceSignature(nonce, s1, s2, userCertificate) {
		SuccessResponse(ms, ServiceType_SIGNED_CHALLENGE)
	} else {
		FailureResponse(ms, ServiceType_SIGNED_CHALLENGE, "verify failed")
	}
	return nil
}

func DoCreate(ms *util.MessageStream, serverData *ServerData, connectionData *ServerConnectionData, msg FileproxyMessage) {
	// Should have two arguments: resourceName, type
	if len(msg.Arguments) < 2 {
		FailureResponse(ms, ServiceType_CREATE, "resource type not specified")
		return
	}
	resourceName := msg.Arguments[0]
	if msg.TypeOfService == nil {
	}

	// Already there?
	info := serverData.ResourceManager.FindResource(resourceName, &serverData.ResourceMutex)
	if info != nil {
		FailureResponse(ms, ServiceType_CREATE, "resource exists")
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
	err = info.AddOwner(*cp, &serverData.ResourceMutex)
	if err != nil {
	}

	// Authorized?
	if !IsAuthorized(*msg.TypeOfService, serverData, connectionData, info) {
		FailureResponse(ms, ServiceType_CREATE, "not authorized")
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
	err = serverData.ResourceManager.InsertResource(info, &serverData.ResourceMutex)

	// Send response
	if err == nil {
		SuccessResponse(ms, ServiceType_CREATE)
	} else {
		FailureResponse(ms, ServiceType_CREATE, "Can't insert resource")
	}
	return
}

func DoDelete(ms *util.MessageStream, serverData *ServerData, connectionData *ServerConnectionData, msg FileproxyMessage) {
	if len(msg.Arguments) < 1 {
	}
	resourceName := msg.Arguments[0]
	info := serverData.ResourceManager.FindResource(resourceName, &serverData.ResourceMutex)
	if info == nil {
		FailureResponse(ms, ServiceType_DELETE, "no such resource")
		return
	}
	if !IsAuthorized(*msg.TypeOfService, serverData, connectionData, info) {
		FailureResponse(ms, ServiceType_DELETE, "not authorized")
		return
	}
	serverData.ResourceManager.DeleteResource(resourceName, &serverData.ResourceMutex)
	SuccessResponse(ms, ServiceType_DELETE)
	return
}

func DoAddOwner(ms *util.MessageStream, serverData *ServerData, connectionData *ServerConnectionData, msg FileproxyMessage) {
	if len(msg.Arguments) < 1 {
	}
	resourceName := msg.Arguments[0]
	info := serverData.ResourceManager.FindResource(resourceName, &serverData.ResourceMutex)
	if info == nil {
		FailureResponse(ms, ServiceType_ADDOWNER, "no such resource")
		return
	}
	if !IsAuthorized(*msg.TypeOfService, serverData, connectionData, info) {
		FailureResponse(ms, ServiceType_ADDOWNER, "not authorized")
		return
	}
	// info.AddOwner(p CombinedPrincipal)
	suc := bool(true)
	if suc {
		SuccessResponse(ms, ServiceType_ADDOWNER)
	} else {
		FailureResponse(ms, ServiceType_ADDOWNER, "Can't insert resource")
	}
	return
}

func DoAddReader(ms *util.MessageStream, serverData *ServerData, connectionData *ServerConnectionData, msg FileproxyMessage) {
	if len(msg.Arguments) < 1 {
	}
	resourceName := msg.Arguments[0]
	info := serverData.ResourceManager.FindResource(resourceName, &serverData.ResourceMutex)
	if info == nil {
		FailureResponse(ms, ServiceType_ADDREADER, "no such resource")
		return
	}
	if !IsAuthorized(*msg.TypeOfService, serverData, connectionData, info) {
		FailureResponse(ms, ServiceType_ADDREADER, "not authorized")
		return
	}
	// info.AddReader(p CombinedPrincipal)
	suc := bool(true)
	if suc {
		SuccessResponse(ms, ServiceType_CREATE)
	} else {
		FailureResponse(ms, ServiceType_CREATE, "Can't insert resource")
	}
	return
}

func DoAddWriter(ms *util.MessageStream, serverData *ServerData, connectionData *ServerConnectionData, msg FileproxyMessage) {
	if len(msg.Arguments) < 1 {
	}
	resourceName := msg.Arguments[0]
	info := serverData.ResourceManager.FindResource(resourceName, &serverData.ResourceMutex)
	if info == nil {
		FailureResponse(ms, ServiceType_ADDWRITER, "no such resource")
		return
	}
	if !IsAuthorized(*msg.TypeOfService, serverData, connectionData, info) {
		FailureResponse(ms, ServiceType_ADDWRITER, "not authorized")
		return
	}
	// info.AddWriter(p CombinedPrincipal)
	suc := bool(true)
	if suc {
		SuccessResponse(ms, ServiceType_CREATE)
	} else {
		FailureResponse(ms, ServiceType_CREATE, "Can't insert resource")
	}
	return
}

func DoDeleteOwner(ms *util.MessageStream, serverData *ServerData, connectionData *ServerConnectionData, msg FileproxyMessage) {
	if len(msg.Arguments) < 1 {
	}
	resourceName := msg.Arguments[0]
	info := serverData.ResourceManager.FindResource(resourceName, &serverData.ResourceMutex)
	if info == nil {
		FailureResponse(ms, ServiceType_DELETEOWNER, "no such resource")
		return
	}
	if !IsAuthorized(*msg.TypeOfService, serverData, connectionData, info) {
		FailureResponse(ms, ServiceType_DELETEOWNER, "not authorized")
		return
	}
	// info.DeleteOwner(p CombinedPrincipal)
	suc := bool(true)
	if suc {
		SuccessResponse(ms, ServiceType_CREATE)
	} else {
		FailureResponse(ms, ServiceType_CREATE, "Can't insert resource")
	}
	return
}

func DoDeleteReader(ms *util.MessageStream, serverData *ServerData, connectionData *ServerConnectionData, msg FileproxyMessage) {
	if len(msg.Arguments) < 1 {
	}
	resourceName := msg.Arguments[0]
	info := serverData.ResourceManager.FindResource(resourceName, &serverData.ResourceMutex)
	if info == nil {
		FailureResponse(ms, ServiceType_DELETEREADER, "no such resource")
		return
	}
	if !IsAuthorized(*msg.TypeOfService, serverData, connectionData, info) {
		FailureResponse(ms, ServiceType_DELETEREADER, "not authorized")
		return
	}
	// info.DeleteWriter(p CombinedPrincipal)
	suc := bool(true)
	if suc {
		SuccessResponse(ms, ServiceType_CREATE)
	} else {
		FailureResponse(ms, ServiceType_CREATE, "Can't insert resource")
	}
	return
}

func DoDeleteWriter(ms *util.MessageStream, serverData *ServerData, connectionData *ServerConnectionData, msg FileproxyMessage) {
	if len(msg.Arguments) < 1 {
	}
	resourceName := msg.Arguments[0]
	info := serverData.ResourceManager.FindResource(resourceName, &serverData.ResourceMutex)
	if info == nil {
		FailureResponse(ms, ServiceType_DELETEWRITER, "no such resource")
		return
	}
	if !IsAuthorized(*msg.TypeOfService, serverData, connectionData, info) {
		FailureResponse(ms, ServiceType_DELETEWRITER, "not authorized")
		return
	}
	// info.DeleteWriter(p CombinedPrincipal)
	suc := bool(true)
	if suc {
		SuccessResponse(ms, ServiceType_CREATE)
	} else {
		FailureResponse(ms, ServiceType_CREATE, "Can't insert resource")
	}
	return
}

func DoReadResource(ms *util.MessageStream, serverData *ServerData, connectionData *ServerConnectionData, msg FileproxyMessage) {
	if len(msg.Arguments) < 1 {
	}
	resourceName := msg.Arguments[0]
	info := serverData.ResourceManager.FindResource(resourceName, &serverData.ResourceMutex)
	if info == nil {
		FailureResponse(ms, ServiceType_READ, "no such resource")
		return
	}
	if !IsAuthorized(*msg.TypeOfService, serverData, connectionData, info) {
		FailureResponse(ms, ServiceType_READ, "not authorized")
		return
	}
	// Send file
	_ = SendFile(ms, serverData, info)
	return
}

func DoWriteResource(ms *util.MessageStream, serverData *ServerData, connectionData *ServerConnectionData, msg FileproxyMessage) {
	if len(msg.Arguments) < 1 {
	}
	resourceName := msg.Arguments[0]
	info := serverData.ResourceManager.FindResource(resourceName, &serverData.ResourceMutex)
	if info == nil {
		FailureResponse(ms, ServiceType_WRITE, "no such resource")
		return
	}
	if !IsAuthorized(*msg.TypeOfService, serverData, connectionData, info) {
		FailureResponse(ms, ServiceType_WRITE, "not authorized")
		return
	}
	// Send file
	_ = GetFile(ms, serverData, info)
	return
}

func DoRequest(ms *util.MessageStream, serverData *ServerData, connectionData *ServerConnectionData, req *FileproxyMessage) {
	fmt.Printf("\nDoRequest:\n")
	PrintMessage(req)
	fmt.Printf("\n")
	if req.TypeOfService == nil {
		FailureResponse(ms, ServiceType_NONE, "Unsupported request")
	}
	switch(*req.TypeOfService) {
	default:
		FailureResponse(ms, *req.TypeOfService, "Unsupported request")
		return
	case ServiceType_REQUEST_CHALLENGE:
		DoChallenge(ms, serverData, connectionData, *req)
		return
	case ServiceType_CREATE:
		DoCreate(ms, serverData, connectionData, *req)
		return
	case ServiceType_DELETE:
		DoDelete(ms, serverData, connectionData, *req)
		return
	case ServiceType_ADDREADER:
		DoAddReader(ms, serverData, connectionData, *req)
		return
	case ServiceType_ADDOWNER:
		DoAddOwner(ms, serverData, connectionData, *req)
		return
	case ServiceType_ADDWRITER:
		DoAddWriter(ms, serverData, connectionData, *req)
		return
	case ServiceType_DELETEREADER:
		DoDeleteReader(ms, serverData, connectionData, *req)
		return
	case ServiceType_DELETEOWNER:
		DoDeleteOwner(ms, serverData, connectionData, *req)
		return
	case ServiceType_DELETEWRITER:
		DoDeleteWriter(ms, serverData, connectionData, *req)
		return
	case ServiceType_READ:
		DoReadResource(ms, serverData, connectionData, *req)
		return
	case ServiceType_WRITE:
		DoWriteResource(ms, serverData, connectionData, *req)
		return
	}
}

