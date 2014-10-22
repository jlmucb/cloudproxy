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
// File: filehandler.go

package fileproxy

import (
	"code.google.com/p/goprotobuf/proto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	tao "github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/util"
	//"flag"
	//"os"
	// "github.com/jlmucb/cloudproxy/tao/auth"
	// taonet "github.com/jlmucb/cloudproxy/tao/net"
)

// Resource types: files, channels
type ResourceInfo struct {
	resourceName      string
	resourceType      string
	resourceStatus    string
	resourceLocation  string
	resourceSize      int
	resourceOwner     string // x509 cert
	dateCreated       string
	dateModified      string
	authenticatorType string // sha hash usually
	authenticator     [][]byte
}

type Principal struct {
	name string
	der  []byte
}

type ResourceMaster struct {
	program        string
	Guard          tao.Guard
	baseDirectory  string
	NumResources   int
	resourceArray  [100]ResourceInfo
	NumPrincipals  int
	principalArray [100]Principal
	// Rules
}

// Policy for managing files in the fileserver.
var policy = []string{
	// Fileserver owns everything.
	"forall FS: forall R: FileServer(FS) and Resource(R) implies Owner(FS, R)",
	// Creators are owners.
	"forall C: forall R: Creator(C, R) implies Owner(C, R)",
	// Owners can perform all actions and make all delegations.
	"forall O: forall A: forall R: Owner(O, R) and Resource(R) and Action(A) implies Authorized(O, \"delegate\", A, R)",
	"forall O: forall A: forall R: Owner(O, R) and Resource(R) and Action(A) implies Authorized(O, A, R)",
	// Principals have namespaces where they can create things.
	// The guard needs to understand that Authorized(P, "create-subdir",
	// path) means that P can create a path with its name underneath (or
	// something like the hash of its name).
	"forall P: Authorized(P, \"execute\") implies Authorized(P, \"create-subdir\", \"/principals\")",
	// Basic Delegation.
	"forall U1: forall U2: forall R: forall A: Authorized(U1, \"delegate\", A, R) and Delegate(U1, U2, A, R) implies Authorized(U2, A, R)",
	// Redelegation.
	"forall U1: forall U2: forall R: forall A: Authorized(U1, \"delegate\", A, R) and Delegate(U1, U2, \"delegate\", A, R) implies Authorized(U2, \"delegate\", A, R)",
}

// Some fake additional statements for the purpose of testing the guard.
var additional_policy = []string{
	"FileServer(\"fileserver\")",
	"Action(\"create\")",
	"Action(\"read\")",
	"Action(\"write\")",
	"Action(\"delete\")",
}

/*
func try(query, msg string, shouldPass bool, g tao.Guard) {
	b, err := g.Query(query)
	if err != nil {
		log.Fatalf("Couldn't query '%s': %s\n", query, err)
	}

	if b != shouldPass {
		log.Fatalln(msg)
	}
}

func delegateResource(owner, delegate, op, res string, g tao.Guard) {
	if err := g.AddRule("Delegate(\"" + owner + "\", \"" + delegate + "\", \"" + op + "\", \"" + res + "\")"); err != nil {
		log.Fatalf("Couldn't delegate operation '%s' on '%s' from '%s' to '%s': %s\n", op, res, owner, delegate, err)
	}
}

func redelegateResource(owner, delegate, op, res string, g tao.Guard) {
	if err := g.AddRule("Delegate(\"" + owner + "\", \"" + delegate + "\", \"delegate\", \"" + op + "\", \"" + res + "\")"); err != nil {
		log.Fatalf("Couldn't redelegate operation '%s' on '%s' from '%s' to '%s': %s\n", op, res, owner, delegate, err)
	}
}
*/

func addResource(creator string, resource string, g tao.Guard) error {
	if err := g.AddRule("Resource(\"" + resource + "\")"); err != nil {
		return errors.New("Cant add resource in rules\n")
	}
	if err := g.AddRule("Creator(\"" + creator + "\", \"" + resource + "\")"); err != nil {
		return errors.New("Cant add creator in rules\n")
	}
	return nil
}

func PrincipalNameFromDERCert(derCert []byte) *string {
	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		fmt.Printf("Cant get name from certificate\n")
		return nil
	}
	cn := cert.Subject.CommonName
	return &cn
}

func makeQuery(subject string, action string, resource string, owner string) *string {
	var out string
	if action == "create" {
		out = "Authorized(\"" + subject + "\", \"" + action + "\",  \"" + resource + "\")"
	} else if action == "read" {
		out = "Authorized(\"" + subject + "\", \"" + action + "\", \"" + resource + "\")"
	} else if action == "write" {
		out = "Authorized(\"" + subject + "\", \"" + action + "\", \"" + resource + "\")"
	} else {
		fmt.Printf("makeQuery: unknown action\n")
		return nil
	}
	fmt.Printf("makeQuery: %s\n", out)
	return &out
}

func (m *ResourceMaster) Query(query string) bool {
	b, err := m.Guard.Query(query)
	if err != nil {
		fmt.Printf("Query: %s generates error %s\n", query, err)
		return false
	}
	if b {
		fmt.Printf("%s succeeds\n", query)
	} else {
		fmt.Printf("%s failed\n", query)
	}
	return b
}

func (m *ResourceMaster) Find(resourcename string) (*ResourceInfo, error) {
	for i := 0; i < m.NumResources; i++ {
		if m.resourceArray[i].resourceName == resourcename {
			return &m.resourceArray[i], nil
		}
	}
	return nil, nil
}

func (m *ResourceMaster) Insert(path string, resourcename string, owner string) (*ResourceInfo, error) {
	found, err := m.Find(resourcename)
	if err != nil {
		return nil, err
	}
	if found != nil {
		return found, nil
	}
	n := m.NumResources
	m.NumResources = m.NumResources + 1
	// resInfo:=   new(ResourceInfo)
	// m.resourceArray[n]=  *resInfo
	m.resourceArray[n].resourceName = resourcename
	m.resourceArray[n].resourceType = "file"
	m.resourceArray[n].resourceStatus = "created"
	m.resourceArray[n].resourceLocation = path + resourcename
	m.resourceArray[n].resourceOwner = owner
	return &m.resourceArray[n], nil
}

func (m *ResourceMaster) FindPrincipal(name string) (*Principal, error) {
	for i := 0; i < m.NumPrincipals; i++ {
		if m.principalArray[i].name == name {
			return &m.principalArray[i], nil
		}
	}
	return nil, nil
}

func (m *ResourceMaster) InsertPrincipal(name string, cert []byte) (*Principal, error) {
	found, err := m.FindPrincipal(name)
	if err != nil {
		return nil, err
	}
	if found != nil {
		return found, nil
	}
	n := m.NumPrincipals
	m.NumPrincipals = m.NumPrincipals + 1
	m.principalArray[n].name = name
	m.principalArray[n].der = cert
	return &m.principalArray[n], nil
}

// return: type, subject, action, resource, owner, status, message, size, buf, error
func DecodeMessage(in []byte) (*int, *string, *string, *string, *string,
	*string, *string, *int, []byte, error) {
	fmt.Printf("filehandler: DecodeMessage\n")
	var the_type32 *int32
	var the_type int
	var subject *string
	var action *string
	var resource *string
	var owner *string
	var status *string
	var message *string
	var size *int
	var buf []byte

	the_type = -1
	the_type32 = nil
	subject = nil
	action = nil
	resource = nil
	owner = nil
	status = nil
	message = nil
	size = nil
	buf = nil

	fpMessage := new(FPMessage)
	err := proto.Unmarshal(in, fpMessage)
	the_type32 = fpMessage.MessageType
	if the_type32 == nil {
		return &the_type, subject, action, resource, owner, status, message, size, buf,
			errors.New("No type")
	}
	the_type = int(*the_type32)
	if the_type == int(MessageType_REQUEST) {
		subject = fpMessage.SubjectName
		action = fpMessage.ActionName
		resource = fpMessage.ResourceName
		owner = fpMessage.ResourceOwner
		return &the_type, subject, action, resource, owner, status, message, size, buf, err
	} else if the_type == int(MessageType_RESPONSE) {
		if fpMessage.StatusOfRequest != nil {
			status = fpMessage.StatusOfRequest
		}
		if fpMessage.MessageFromRequest != nil {
			message = fpMessage.MessageFromRequest
		}
		return &the_type, subject, action, resource, owner, status, message, size, buf, err
	} else if the_type == int(MessageType_FILE_NEXT) || the_type == int(MessageType_FILE_LAST) {
		size32 := *fpMessage.BufferSize
		size1 := int(size32)
		size = &size1
		str := fpMessage.TheBuffer
		buf = []byte(*str)
		return &the_type, subject, action, resource, owner, status, message, size, buf, nil
	} else if the_type == int(MessageType_PROTOCOL_RESPONSE) {
		size32 := *fpMessage.BufferSize
		size1 := int(size32)
		size = &size1
		str := fpMessage.TheBuffer
		buf = []byte(*str)
		return &the_type, subject, action, resource, owner, status, message, size, buf, nil
	} else {
		fmt.Printf("Decode message bad message type %d\n", the_type)
		return &the_type, subject, action, resource, owner, status, message, size, buf,
			errors.New("Unknown message type")
	}
}

func EncodeMessage(theType int, subject *string, action *string, resourcename *string, owner *string,
	status *string, reqMessage *string, size *int, buf []byte) ([]byte, error) {
	fmt.Printf("filehandler: encodeMessage\n")
	fmt.Printf("EncodeMessage %d\n", theType)
	protoMessage := new(FPMessage)
	protoMessage.MessageType = proto.Int(theType)
	if theType == int(MessageType_REQUEST) {
		protoMessage.SubjectName = proto.String(*subject)
		protoMessage.ActionName = proto.String(*action)
		protoMessage.ResourceName = proto.String(*resourcename)
		protoMessage.ResourceOwner = proto.String(*owner)
	} else if theType == int(MessageType_RESPONSE) {
		protoMessage.StatusOfRequest = proto.String(*status)
		protoMessage.MessageFromRequest = proto.String(*reqMessage)
	} else if theType == int(MessageType_FILE_NEXT) || theType == int(MessageType_FILE_LAST) {
		protoMessage.BufferSize = proto.Int(*size)
		protoMessage.TheBuffer = proto.String(string(buf))
	} else if theType == int(MessageType_PROTOCOL_RESPONSE) {
		protoMessage.BufferSize = proto.Int(*size)
		protoMessage.TheBuffer = proto.String(string(buf))
	} else {
		fmt.Print("EncodeMessage, Bad message type: %d\n", theType)
		return nil, errors.New("encodemessage, unknown message type\n")
	}
	out, err := proto.Marshal(protoMessage)
	fmt.Printf("Marshaled %d\n", len(out))
	return out, err
}

func (m *ResourceMaster) Delete(resourceName string) error {
	return nil // not implemented
}

func (m *ResourceMaster) EncodeMaster() ([]byte, error) {
	fmt.Printf("filehandler: encodeMaster\n")
	protoMessage := new(FPResourceMaster)
	protoMessage.PrinName = proto.String(m.program)
	protoMessage.BaseDirectoryName = proto.String(m.baseDirectory)
	protoMessage.NumFileinfos = proto.Int(len(m.resourceArray))
	out, err := proto.Marshal(protoMessage)
	return out, err
}

func (m *ResourceMaster) DecodeMaster(in []byte) (*int, error) {
	fmt.Printf("filehandler: DecodeMaster\n")
	rMessage := new(FPResourceMaster)
	_ = proto.Unmarshal(in, rMessage)
	m.program = *rMessage.PrinName
	m.baseDirectory = *rMessage.BaseDirectoryName
	size := *rMessage.NumFileinfos
	isize := int(size) //TODO: Fix
	return &isize, nil
}

func (r *ResourceInfo) EncodeResourceInfo() ([]byte, error) {
	fmt.Printf("filehandler: encodeResourceInfo\n")
	protoMessage := new(FPResourceInfo)
	protoMessage.ResourceName = proto.String(r.resourceName)
	protoMessage.ResourceType = proto.String(r.resourceType)
	protoMessage.ResourceStatus = proto.String(r.resourceStatus)
	protoMessage.ResourceLocation = proto.String(r.resourceLocation)
	protoMessage.ResourceSize = proto.Int(r.resourceSize)
	//Fix: protoMessage.ResourceOwner= proto.Bytes(r.resourceOwner);
	out, err := proto.Marshal(protoMessage)
	return out, err
}

func (r *ResourceInfo) DecodeResourceInfo(in []byte) error {
	fmt.Printf("filehandler: DecodeResourceInfo\n")
	rMessage := new(FPResourceInfo)
	_ = proto.Unmarshal(in, rMessage)
	r.resourceName = *rMessage.ResourceName
	r.resourceType = *rMessage.ResourceType
	r.resourceLocation = *rMessage.ResourceLocation
	r.resourceSize = int(*rMessage.ResourceSize)
	r.resourceOwner = *rMessage.ResourceOwner
	return nil
}

func (r *ResourceInfo) PrintResourceInfo() {
	fmt.Printf("Resource name: %s\n", r.resourceName)
	fmt.Printf("Resource type: %s\n", r.resourceType)
	fmt.Printf("Resource status: %s\n", r.resourceStatus)
	fmt.Printf("Resource location: %s\n", r.resourceLocation)
	fmt.Printf("Resource size: %d\n", r.resourceSize)
	fmt.Printf("Resource creation date: %s\n", r.dateCreated)
	fmt.Printf("Resource modified date: %s\n", r.dateModified)
	fmt.Printf("\n")
}

func (m *ResourceMaster) PrintMaster(printResources bool) {
	fmt.Printf("Program principal: %s\n", m.program)
	fmt.Printf("Base Directory: %s\n", m.baseDirectory)
	fmt.Printf("%d resources\n", len(m.resourceArray))
	if printResources {
		for i := 0; i < len(m.resourceArray); i++ {
			m.resourceArray[i].PrintResourceInfo()
		}
	}
}

func (m *ResourceMaster) InitGuard(rulefile string) error {
	fmt.Printf("filehandler: InitGuard\n")
	m.Guard = tao.NewTemporaryDatalogGuard()
	for _, r := range policy {
		if err := m.Guard.AddRule(r); err != nil {
			return errors.New("Couldn't add rule in InitGuard")
		}
	}

	for _, r := range additional_policy {
		if err := m.Guard.AddRule(r); err != nil {
			return errors.New("Couldn't add rule in InitGuard")
		}
	}

	/*
		// The FileServer owns the test resource.
		try("Owner(\"FServer\", \"test\")",
		    "The FileServer doesn't own the test resource, but it should",
		    true,
		    td)
	*/
	// Remove this
	m.Guard = tao.LiberalGuard

	return nil
}

func (m *ResourceMaster) SaveRules(g tao.Guard, rulefile string) error {
	fmt.Printf("filehandler: SaveRules\n")
	// no need for rules
	return nil
}

func (m *ResourceMaster) GetResourceData(masterInfoFile string, resourceInfoArrayFile string) error {
	fmt.Printf("filehandler: GetResourceData\n")
	// read master info
	// decrypt it
	// read resourceinfos
	// decrypt it

	// read rule file
	// decrypt it
	return nil
}

func (m *ResourceMaster) SaveResourceData(masterInfoFile string, resourceInfoArrayFile string) error {
	fmt.Printf("filehandler: SaveResourceData\n")
	// encrypt master info
	// write master info
	// encrypt fileinfos
	// write fileinfos
	// encrypt rules
	// write rules
	return nil
}

// return values: subject, action, resourcename, size, error
func EncodeRequest(subject string, action string, resourcename string, owner string) ([]byte, error) {
	fmt.Printf("filehandler: encodeRequest\n")
	out, err := EncodeMessage(int(MessageType_REQUEST), &subject, &action, &resourcename, &owner,
		nil, nil, nil, nil)
	return out, err
}

// return values: subject, action, resourcename, owner, error
func DecodeRequest(in []byte) (*string, *string, *string, *string, error) {
	fmt.Printf("filehandler: DecodeRequest\n")
	theType, subject, action, resource, owner, status, message, size, buf, err := DecodeMessage(in)
	if err != nil {
		fmt.Printf("DecodeRequest error: ", err)
		fmt.Printf("\n")
		return nil, nil, nil, nil, err
	}
	PrintRequest(subject, action, resource, owner)
	if *theType != int(MessageType_REQUEST) {
		return nil, nil, nil, nil, errors.New("Cant Decode request")
	}
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if status != nil || message != nil || size != nil || buf != nil {
		return nil, nil, nil, nil, errors.New("malformed request")
	}
	return subject, action, resource, owner, nil
}

func PrintRequest(subject *string, action *string, resource *string, owner *string) {
	fmt.Printf("PrintRequest\n")
	if subject != nil {
		fmt.Printf("\tsubject: %s\n", *subject)
	}
	if action != nil {
		fmt.Printf("\taction: %s\n", *action)
	}
	if resource != nil {
		fmt.Printf("\tresource: %s\n", *resource)
	}
	if owner != nil {
		fmt.Printf("\towner: %s\n", *owner)
	}
}

// return: status, message, size, error
func GetResponse(ms *util.MessageStream) (*string, *string, *int, error) {
	fmt.Printf("filehandler: GetResponse\n")
	strbytes, err := ms.ReadString()
	if err != nil {
		return nil, nil, nil, err
	}
	fmt.Printf("GetResponse read %d bytes\n", len(strbytes))
	theType, _, _, _, _, status, message, size, _, err := DecodeMessage([]byte(strbytes))
	if err != nil {
		fmt.Printf("DecodeMessage error in GetResponse\n")
		return nil, nil, nil, err
	}
	if status == nil {
		fmt.Printf("DecodeMessage in getresponse returned nil status")
	} else {
		fmt.Printf("DecodeMessage in getresponse returned %s (status)\n", *status)
	}
	fmt.Printf("GetResponse %d\n", len(strbytes))
	if *theType != int(MessageType_RESPONSE) {
		return nil, nil, nil, errors.New("Wrong message type")
	}
	return status, message, size, nil
}

func PrintResponse(status *string, message *string, size *int) {
	fmt.Printf("PrintResponse\n")
	if status != nil {
		fmt.Printf("\tstatus: %s\n", *status)
	} else {
		fmt.Printf("\tstatus: empty\n")
	}
	if message != nil {
		fmt.Printf("\tmessage: %s\n", *message)
	}
	if size != nil {
		fmt.Printf("\tsize: %d\n", *size)
	}
}

func SendResponse(ms *util.MessageStream, status string, message string, size int) error {
	out, err := EncodeMessage(int(MessageType_RESPONSE), nil, nil, nil, nil, &status, &message, &size, nil)
	if err != nil {
		fmt.Printf("EncodeMessage fails in SendResponse\n")
		return err
	}
	send := string(out)
	fmt.Printf("filehandler: SendResponse sending %s %s %d\n", status, message, len(send))
	n, err := ms.WriteString(send)
	if err != nil {
		fmt.Printf("filehandler: SendResponse Writestring error %d\n", n, err)
		return err
	}
	return nil
}

func SendProtocolMessage(ms *util.MessageStream, size int, buf []byte) error {
	fmt.Printf("filehandler: SendProtocolMessage\n")
	out, err := EncodeMessage(int(MessageType_PROTOCOL_RESPONSE), nil, nil, nil, nil, nil, nil, &size, buf)
	if err != nil {
		fmt.Printf("EncodeMessage fails in SendProtocolMessage\n")
		return err
	}
	send := string(out)
	n, err := ms.WriteString(send)
	if err != nil {
		fmt.Printf("filehandler: SendProtocolMessage Writestring error %d\n", n, err)
		return err
	}
	return nil
}

func GetProtocolMessage(ms *util.MessageStream) ([]byte, error) {
	fmt.Printf("filehandler: GetProtocolMessage\n")
	strbytes, err := ms.ReadString()
	if err != nil {
		return nil, err
	}
	fmt.Printf("GetProtocolMessage read %d bytes\n", len(strbytes))
	theType, _, _, _, _, _, _, _, out, err := DecodeMessage([]byte(strbytes))
	if err != nil {
		fmt.Printf("DecodeMessage error in GetProtocolMessage\n")
		return nil, err
	}
	if *theType != int(MessageType_PROTOCOL_RESPONSE) {
		return nil, errors.New("Wrong message type")
	}
	return out, nil
}

func AuthenticatePrincipal(m *ResourceMaster, ms *util.MessageStream) (bool, []byte) {
	fmt.Printf("AuthenticatePrincipal\n")
	offeredCert, err := GetProtocolMessage(ms)
	if err != nil {
		fmt.Printf("cant GetProtocolMessage in AuthenticatePrincipal % x\n", offeredCert)
	}
	fmt.Printf("AuthenticatePrincipal: got offered cert\n")
	c := 32
	b := make([]byte, c)
	_, err = rand.Read(b)
	if err != nil {
		fmt.Printf("Rand error in AuthenticatePrincipal\n")
	}
	fmt.Printf("nonce: % x\n", b)
	SendProtocolMessage(ms, len(b), b)
	fmt.Printf("AuthenticatePrincipal: sent nonce\n")
	signedRand, err := GetProtocolMessage(ms)
	if err != nil {
		fmt.Printf("cant GetProtocolMessage in AuthenticatePrincipal\n")
	}
	fmt.Printf("AuthenticatePrincipal: got signed nonce % x\n", signedRand)
	// decrypt nonce
	status := "succeeded"
	msg := ""
	SendResponse(ms, status, msg, 0)
	return true, offeredCert
}

func AuthenticatePrincipalRequest(ms *util.MessageStream, key *tao.Keys, derCert []byte) bool {
	fmt.Printf("AuthenticatePrincipalRequest\n")
	// format request
	subject := "jlm"
	action := "authenticateprincipal"
	owner := "jlm"
	message, err := EncodeMessage(int(MessageType_REQUEST), &subject, &action, &subject, &owner,
		nil, nil, nil, nil)
	if err != nil {
		fmt.Printf("AuthenticatePrincipalRequest couldnt build request\n")
		return false
	}
	fmt.Printf("AuthenticatePrincipalRequest request %d, ", len(message))
	fmt.Printf("\n")
	_, _ = ms.WriteString(string(message))
	fmt.Printf("AuthenticatePrincipalRequest: sent request\n")
	SendProtocolMessage(ms, len(derCert), derCert)
	fmt.Printf("AuthenticatePrincipalRequest: sent cert\n")
	nonce, err := GetProtocolMessage(ms)
	if err != nil {
		fmt.Printf("cant GetProtocolMessage in AuthenticatePrincipalRequest\n")
		return false
	}
	fmt.Printf("AuthenticatePrincipalRequest: got nonce\n")
	// encrypt nonce
	SendProtocolMessage(ms, len(nonce), nonce)
	fmt.Printf("AuthenticatePrincipalRequest: sent signed\n")
	status, _, _, err := GetResponse(ms)
	if err != nil {
		fmt.Printf("cant GetResponse in AuthenticatePrincipalRequest\n")
		return false
	}
	fmt.Printf("AuthenticatePrincipalRequest: status of response: %s\n", *status)
	return true
}

func readRequest(m *ResourceMaster, ms *util.MessageStream, resourcename string) error {
	fmt.Printf("filehandler: readRequest\n")
	rInfo, _ := m.Find(resourcename)
	if rInfo == nil {
		SendResponse(ms, "failed", "resource does not exist", 0)
		return nil
	}
	status := "succeeded"
	SendResponse(ms, status, "", 0)
	return SendFile(ms, m.baseDirectory, resourcename, nil)
}

func writeRequest(m *ResourceMaster, ms *util.MessageStream, resourcename string) error {
	fmt.Printf("filehandler: writeRequest\n")
	rInfo, _ := m.Find(resourcename)
	if rInfo == nil {
		SendResponse(ms, "failed", "resource does not exist", 0)
		return nil
	}
	status := "succeeded"
	SendResponse(ms, status, "", 0)
	return GetFile(ms, m.baseDirectory, resourcename, nil)
}

func createRequest(m *ResourceMaster, ms *util.MessageStream,
	resourcename string, owner string) error {
	fmt.Printf("filehandler: createRequest\n")
	rInfo, _ := m.Find(resourcename)
	if rInfo != nil {
		SendResponse(ms, "failed", "resource exists", 0)
		return nil
	}
	// Is it authorized
	rInfo, _ = m.Insert(m.baseDirectory, resourcename, owner)
	if rInfo == nil {
		SendResponse(ms, "failed", "cant insert resource", 0)
		return nil
	}
	rInfo.PrintResourceInfo()
	status := "succeeded"
	SendResponse(ms, status, "", 0)
	addResource(owner, resourcename, m.Guard)
	return nil
}

func deleteRequest(m *ResourceMaster, ms *util.MessageStream, resourcename string) error {
	return errors.New("deleteRequest not implemented")
}

func addRuleRequest(m *ResourceMaster, ms *util.MessageStream, resourcename string) error {
	return errors.New("addRuleRequest not implemented")
}

func addOwnerRequest(m *ResourceMaster, ms *util.MessageStream, resourcename string) error {
	return errors.New("addOwnerRequest not implemented")
}

func deleteOwnerRequest(m *ResourceMaster, ms *util.MessageStream, resourcename string) error {
	return errors.New("deleteOwnerRequest not implemented")
}

// first return value is terminate flag
func (m *ResourceMaster) HandleServiceRequest(ms *util.MessageStream, request []byte) (bool, error) {
	fmt.Printf("filehandler: HandleServiceRequest\n")
	subject, action, resourcename, owner, err := DecodeRequest(request)
	if err != nil {
		return false, err
	}
	fmt.Printf("HandleServiceRequest\n")
	PrintRequest(subject, action, resourcename, owner)

	if *action == "authenticateprincipal" {
		ok, ownerCert := AuthenticatePrincipal(m, ms)
		if !ok {
			ownerName := PrincipalNameFromDERCert([]byte(ownerCert))
			_, err = m.InsertPrincipal(*ownerName, []byte(ownerCert))
			if err != nil {
				fmt.Printf("cant insert principal name in file\n")
				return false, errors.New("cant insert principal name in file")
			}
			status := "succeeded"
			message := ""
			SendResponse(ms, status, message, 0)
			return false, nil
		} else {
			return false, errors.New("AuthenticatePrincipal failed")
		}
	}

	// replace owner with name
	var ownerName *string
	ownerName = nil
	if owner != nil {
		// enable the following as soon as we send certs
		/*
			ownerName= PrincipalNameFromDERCert(*owner)
			if(ownerName==nil) {
				status:= "failed"
				message:= "unknown owner specified"
				SendResponse(ms, status, message, 0);
			}
			return false, errors.New("unknown owner")
		*/
		ownerName = owner
	}

	// is it authorized?
	var ok bool
	if *action == "create" {
		fileserverSubject := "fileserver"
		query := makeQuery(fileserverSubject, *action, *resourcename, *ownerName)
		if query == nil {
			fmt.Printf("bad query")
		}
		ok = m.Query(*query)
	} else {
		ok = true
	}
	if ok == false {
		status := "failed"
		message := "unauthorized"
		SendResponse(ms, status, message, 0)
		return false, nil
	}

	if *action == "create" {
		if resourcename == nil || ownerName == nil {
			return false, errors.New("Nil parameters for createRequest")
		}
		err := createRequest(m, ms, *resourcename, *ownerName)
		return false, err
	} else if *action == "delete" {
		err := deleteRequest(m, ms, *resourcename)
		return false, err
	} else if *action == "getfile" {
		err := readRequest(m, ms, *resourcename)
		return false, err
	} else if *action == "sendfile" {
		err := writeRequest(m, ms, *resourcename)
		return false, err
	} else if *action == "terminate" {
		return true, nil
	} else {
		status := "failed"
		message := "unsupported action"
		SendResponse(ms, status, message, 0)
		return false, errors.New("unsupported action")
	}
}

func (m *ResourceMaster) InitMaster(filepath string, masterInfoDir string, prin string) error {
	fmt.Printf("filehandler: InitMaster\n")
	m.GetResourceData(masterInfoDir+"masterinfo", masterInfoDir+"resources")
	m.NumResources = 0
	m.NumPrincipals = 0
	m.baseDirectory = filepath
	m.InitGuard(masterInfoDir + "rules")
	return nil
}

func (m *ResourceMaster) SaveMaster(masterInfoDir string) error {
	fmt.Printf("filehandler: SaveMaster\n")
	err := m.SaveResourceData(masterInfoDir+"masterinfo", masterInfoDir+"resources")
	if err != nil {
		fmt.Printf("filehandler: cant m.SaveResourceData\n")
		return err
	}
	return m.SaveRules(m.Guard, masterInfoDir+"rules")
}
