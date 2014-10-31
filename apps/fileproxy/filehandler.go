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
// File: filehandler.go

package fileproxy

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"log"
	"os"

	"code.google.com/p/goprotobuf/proto"

	tao "github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/util"
)

const SizeofNonce = 32
const ChallengeContext = "fileproxy-challenge"

type ProgramPolicy struct {
	Initialized   bool
	ThePolicyCert []byte
	MySigningKey  tao.Keys
	MySymKeys     []byte
	MyProgramCert []byte
}

var MyProgramPolicy ProgramPolicy

func InitProgramPolicy(policyCert []byte, signingKey tao.Keys, symKeys []byte, programCert []byte) bool {
	MyProgramPolicy.ThePolicyCert = policyCert
	MyProgramPolicy.MySigningKey = signingKey
	MyProgramPolicy.MySymKeys = symKeys
	MyProgramPolicy.MyProgramCert = programCert
	MyProgramPolicy.Initialized = true
	return true
}

type NameandHash struct {
	ItemName string
	Hash     []byte
}

type RollbackMaster struct {
	ProgramName string
	Counter     int64
	// TODO: change magic allocation sizes
	NameandHashArray [100]NameandHash
}

// Resource types: files, channels
type ResourceInfo struct {
	ResourceName      string
	ResourceType      string
	ResourceStatus    string
	ResourceLocation  string
	ResourceSize      int
	ResourceOwner     string
	DateCreated       string
	DateModified      string
	AuthenticatorType string
	Authenticator     [][]byte
}

type Principal struct {
	Name   string
	Der    []byte
	Status string
}

type ResourceMaster struct {
	ProgramName   string
	Guard         tao.Guard
	BaseDirectory string
	NumResources  int
	// TODO: change magic allocation sizes
	ResourceArray    [100]ResourceInfo
	NumPrincipals    int
	PrincipalArray   [100]Principal
	Policy           []string
	AdditionalPolicy []string
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
	"Action(\"getfile\")",
	"Action(\"sendfile\")",
	"Action(\"delete\")",
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

func addResource(creator, resource string, g tao.Guard) error {
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
		log.Printf("filehandler: Cant get name from certificate\n")
		return nil
	}
	cn := cert.Subject.CommonName
	return &cn
}

func makeQuery(subject string, action string, resource string) *string {
	var out string
	if action == "create" {
		out = "Authorized(\"" + subject + "\", \"" + action + "\",  \"" + resource + "\")"
	} else if action == "getfile" {
		out = "Authorized(\"" + subject + "\", \"" + action + "\", \"" + resource + "\")"
	} else if action == "sendfile" {
		out = "Authorized(\"" + subject + "\", \"" + action + "\", \"" + resource + "\")"
	} else {
		log.Printf("makeQuery: unknown action\n")
		return nil
	}
	log.Printf("makeQuery: %s\n", out)
	return &out
}

func (m *ResourceMaster) Query(query string) bool {
	b, err := m.Guard.Query(query)
	if err != nil {
		log.Printf("Query: %s generates error %s\n", query, err)
		return false
	}
	if b {
		log.Printf("%s succeeds\n", query)
	} else {
		log.Printf("%s failed\n", query)
	}
	return b
}

func (m *ResourceMaster) Find(resourcename string) (*ResourceInfo, error) {
	for _, r := range m.ResourceArray {
		if r.ResourceName == resourcename {
			return &r, nil
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
	m.ResourceArray[n].ResourceName = resourcename
	m.ResourceArray[n].ResourceType = "file"
	m.ResourceArray[n].ResourceStatus = "created"
	m.ResourceArray[n].ResourceLocation = path + resourcename
	m.ResourceArray[n].ResourceOwner = owner
	return &m.ResourceArray[n], nil
}

func (m *ResourceMaster) FindPrincipal(name string) (*Principal, error) {
	for _, r := range m.PrincipalArray {
		if r.Name == name {
			return &r, nil
		}
	}
	return nil, nil
}

func (m *ResourceMaster) InsertPrincipal(name string, cert []byte, authStatus string) (*Principal, error) {
	found, err := m.FindPrincipal(name)
	if err != nil {
		return nil, err
	}
	if found != nil {
		return found, nil
	}
	n := m.NumPrincipals
	m.NumPrincipals = m.NumPrincipals + 1
	m.PrincipalArray[n].Name = name
	m.PrincipalArray[n].Der = cert
	m.PrincipalArray[n].Status = authStatus
	return &m.PrincipalArray[n], nil
}

func DecodeMessage(in []byte) (*int, *string, *string, *string, *string,
	*string, *string, *int, []byte, error) {

	log.Printf("filehandler: DecodeMessage\n")

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
		log.Printf("Decode message bad message type %d\n", the_type)
		return &the_type, subject, action, resource, owner, status, message, size, buf,
			errors.New("Unknown message type")
	}
}

func EncodeMessage(theType int, subject *string, action *string, resourcename *string, owner *string,
	status *string, reqMessage *string, size *int, buf []byte) ([]byte, error) {
	log.Printf("filehandler: encodeMessage\n")
	log.Printf("EncodeMessage %d\n", theType)
	protoMessage := new(FPMessage)
	protoMessage.MessageType = proto.Int(theType)
	if theType == int(MessageType_REQUEST) {
		protoMessage.SubjectName = proto.String(*subject)
		protoMessage.ActionName = proto.String(*action)
		protoMessage.ResourceName = proto.String(*resourcename)
		if owner != nil {
			protoMessage.ResourceOwner = proto.String(*owner)
		}
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
		log.Print("EncodeMessage, Bad message type: %d\n", theType)
		return nil, errors.New("encodemessage, unknown message type\n")
	}
	out, err := proto.Marshal(protoMessage)
	log.Printf("Marshaled %d\n", len(out))
	return out, err
}

func (m *ResourceMaster) Delete(resourceName string) error {
	return nil // not implemented
}

func (m *ResourceMaster) EncodeMaster() ([]byte, error) {
	log.Printf("filehandler: encodeMaster\n")
	protoMessage := new(FPResourceMaster)
	protoMessage.PrinName = proto.String(m.ProgramName)
	protoMessage.BaseDirectoryName = proto.String(m.BaseDirectory)
	protoMessage.NumFileinfos = proto.Int(len(m.ResourceArray))
	return proto.Marshal(protoMessage)
}

func (m *ResourceMaster) DecodeMaster(in []byte) (*int, error) {
	log.Printf("filehandler: DecodeMaster\n")
	rMessage := new(FPResourceMaster)
	err := proto.Unmarshal(in, rMessage)
	if err != nil {
		return nil, err
	}
	m.ProgramName = *rMessage.PrinName
	m.BaseDirectory = *rMessage.BaseDirectoryName
	size := *rMessage.NumFileinfos
	isize := int(size) //TODO: Fix
	return &isize, nil
}

func (m *ResourceMaster) PrintMaster(printResources bool) {
	log.Printf("Program principal: %s\n", m.ProgramName)
	log.Printf("Base Directory: %s\n", m.BaseDirectory)
	log.Printf("%d resources\n", len(m.ResourceArray))
	if printResources {
		for _, r := range m.ResourceArray {
			r.PrintResourceInfo()
		}
	}
}

func (r *ResourceInfo) EncodeResourceInfo() ([]byte, error) {
	log.Printf("filehandler: encodeResourceInfo\n")
	protoMessage := new(FPResourceInfo)
	protoMessage.ResourceName = proto.String(r.ResourceName)
	protoMessage.ResourceType = proto.String(r.ResourceType)
	protoMessage.ResourceStatus = proto.String(r.ResourceStatus)
	protoMessage.ResourceLocation = proto.String(r.ResourceLocation)
	protoMessage.ResourceSize = proto.Int(r.ResourceSize)
	//Fix: protoMessage.ResourceOwner= proto.Bytes(r.ResourceOwner);
	out, err := proto.Marshal(protoMessage)
	return out, err
}

func (r *ResourceInfo) DecodeResourceInfo(in []byte) error {
	log.Printf("filehandler: DecodeResourceInfo\n")
	rMessage := new(FPResourceInfo)
	_ = proto.Unmarshal(in, rMessage)
	r.ResourceName = *rMessage.ResourceName
	r.ResourceType = *rMessage.ResourceType
	r.ResourceLocation = *rMessage.ResourceLocation
	r.ResourceSize = int(*rMessage.ResourceSize)
	r.ResourceOwner = *rMessage.ResourceOwner
	return nil
}

func (r *ResourceInfo) PrintResourceInfo() {
	log.Printf("Resource name: %s\n", r.ResourceName)
	log.Printf("Resource type: %s\n", r.ResourceType)
	log.Printf("Resource status: %s\n", r.ResourceStatus)
	log.Printf("Resource location: %s\n", r.ResourceLocation)
	log.Printf("Resource size: %d\n", r.ResourceSize)
	log.Printf("Resource creation date: %s\n", r.DateCreated)
	log.Printf("Resource modified date: %s\n", r.DateModified)
	log.Printf("\n")
}

func (p *Principal) EncodePrincipal() ([]byte, error) {
	log.Printf("filehandler: encodePrincipalInfo\n")
	protoMessage := new(FPPrincipalInfo)
	protoMessage.PrincipalName = proto.String(p.Name)
	protoMessage.PrincipalStatus = proto.String(p.Status)
	protoMessage.PrincipalCert = proto.String(string(p.Der))
	out, err := proto.Marshal(protoMessage)
	return out, err
}

func (p *Principal) DecodePrincipal(in []byte) error {
	log.Printf("filehandler: DecodePrincipalInfo\n")
	rMessage := new(FPPrincipalInfo)
	_ = proto.Unmarshal(in, rMessage)
	p.Name = *rMessage.PrincipalName
	p.Status = *rMessage.PrincipalStatus
	p.Der = []byte(*rMessage.PrincipalCert)
	return nil
}

func (p *Principal) PrintPrincipal() {
	log.Printf("Principal name: %s\n", p.Name)
	log.Printf("Principal status: %s\n", p.Status)
	log.Printf("Principal cert: %s\n", p.Der)
	log.Printf("\n")
}

func (m *ResourceMaster) PrintAllPolicy() {
	for _, r := range m.Policy {
		log.Printf("Rule: %s\n", r)
	}
	for _, r := range m.AdditionalPolicy {
		log.Printf("Rule: %s\n", r)
	}
}

func (m *ResourceMaster) InitGuard(rulefile string) error {
	log.Printf("filehandler: InitGuard\n")
	m.Guard = tao.NewTemporaryDatalogGuard()
	for _, r := range m.Policy {
		if err := m.Guard.AddRule(r); err != nil {
			return errors.New("Couldn't add rule in InitGuard")
		}
	}

	for _, r := range m.AdditionalPolicy {
		if err := m.Guard.AddRule(r); err != nil {
			return errors.New("Couldn't add rule in InitGuard")
		}
	}
	return nil
}

func (m *ResourceMaster) ReadRules(rulefile string) error {
	log.Printf("filehandler: ReadRules\n")
	// no need for rules
	return nil
}

func (m *ResourceMaster) SaveRules(rulefile string) error {
	log.Printf("filehandler: SaveRules\n")
	// no need for rules
	return nil
}

func (m *ResourceMaster) GetResourceData(masterFile string, resourceFile string, principalFile string, ruleFile string) error {
	log.Printf("filehandler: GetResourceData\n")
	// TODO: decrypt the files
	// Read master
	masterRecord, _ := ioutil.ReadFile(masterFile)
	_, _ = m.DecodeMaster([]byte(masterRecord))
	log.Printf("masterRecord size: %d\n", len(masterRecord))

	// Save resources
	fo, _ := os.Open(resourceFile)
	rs := util.NewMessageStream(fo)
	for _, r := range m.ResourceArray {
		resourceRecord, _ := rs.ReadString()
		_ = r.DecodeResourceInfo([]byte(resourceRecord))
		log.Printf("resourceRecord size: %d\n", len(resourceRecord))
	}
	fo.Close()

	// Read principals
	fo, _ = os.Open(principalFile)
	ps := util.NewMessageStream(fo)
	for _, p := range m.PrincipalArray {
		principalRecord, _ := ps.ReadString()
		_ = p.DecodePrincipal([]byte(principalRecord))
		log.Printf("principalRecord size: %d\n", len(principalRecord))
	}
	fo.Close()

	// Read rules
	_ = m.ReadRules(ruleFile)
	return nil
}

func (m *ResourceMaster) SaveResourceData(masterFile string, resourceFile string, principalFile string, ruleFile string) error {
	log.Printf("filehandler: SaveResourceData\n")
	// TODO: encrypt the files
	// Save master
	masterRecord, _ := m.EncodeMaster()
	log.Printf("masterRecord size: %d\n", len(masterRecord))
	ioutil.WriteFile(masterFile, masterRecord, os.ModePerm)
	// Save resources
	fo, _ := os.Create(resourceFile)
	rs := util.NewMessageStream(fo)
	for _, r := range m.ResourceArray {
		resourceRecord, _ := r.EncodeResourceInfo()
		log.Printf("resourceRecord size: %d\n", len(resourceRecord))
		_, _ = rs.WriteString(string(resourceRecord))
	}
	fo.Close()
	// Save principals
	fo, _ = os.Create(principalFile)
	ps := util.NewMessageStream(fo)
	for _, p := range m.PrincipalArray {
		principalRecord, _ := p.EncodePrincipal()
		log.Printf("principalRecord size: %d\n", len(principalRecord))
		_, _ = ps.WriteString(string(principalRecord))
	}
	fo.Close()

	// Save rules
	_ = m.SaveRules(ruleFile)
	return nil
}

func EncodeRequest(subject string, action string, resourcename string, owner string) ([]byte, error) {
	log.Printf("filehandler: encodeRequest\n")
	out, err := EncodeMessage(int(MessageType_REQUEST), &subject, &action, &resourcename, &owner,
		nil, nil, nil, nil)
	return out, err
}

func DecodeRequest(in []byte) (*string, *string, *string, *string, error) {
	log.Printf("filehandler: DecodeRequest\n")
	theType, subject, action, resource, owner, status, message, size, buf, err := DecodeMessage(in)
	if err != nil {
		log.Printf("DecodeRequest error: ", err)
		log.Printf("\n")
		return nil, nil, nil, nil, err
	}
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

func PrintRequest(subject []byte, action *string, resource *string, owner []byte) {
	log.Printf("PrintRequest\n")
	if subject != nil {
		log.Printf("\tsubject: % x\n", subject)
		subjectName := PrincipalNameFromDERCert(subject)
		if subjectName != nil {
			log.Printf("\tsubject: %s\n", *subjectName)
		}
	}
	if action != nil {
		log.Printf("\taction: %s\n", *action)
	}
	if resource != nil {
		log.Printf("\tresource: %s\n", *resource)
	}
	if owner != nil {
		log.Printf("\towner: % x\n", owner)
		ownerName := PrincipalNameFromDERCert(owner)
		if ownerName != nil {
			log.Printf("\towner: %s\n", *ownerName)
		}
	}
}

func GetResponse(ms *util.MessageStream) (*string, *string, *int, error) {
	log.Printf("filehandler: GetResponse\n")
	strbytes, err := ms.ReadString()
	if err != nil {
		return nil, nil, nil, err
	}
	log.Printf("GetResponse read %d bytes\n", len(strbytes))
	theType, _, _, _, _, status, message, size, _, err := DecodeMessage([]byte(strbytes))
	if err != nil {
		log.Printf("DecodeMessage error in GetResponse\n")
		return nil, nil, nil, err
	}
	if status == nil {
		log.Printf("DecodeMessage in getresponse returned nil status")
	} else {
		log.Printf("DecodeMessage in getresponse returned %s (status)\n", *status)
	}
	log.Printf("GetResponse %d\n", len(strbytes))
	if *theType != int(MessageType_RESPONSE) {
		return nil, nil, nil, errors.New("Wrong message type")
	}
	return status, message, size, nil
}

func PrintResponse(status *string, message *string, size *int) {
	log.Printf("PrintResponse\n")
	if status != nil {
		log.Printf("\tstatus: %s\n", *status)
	} else {
		log.Printf("\tstatus: empty\n")
	}
	if message != nil {
		log.Printf("\tmessage: %s\n", *message)
	}
	if size != nil {
		log.Printf("\tsize: %d\n", *size)
	}
}

func SendResponse(ms *util.MessageStream, status string, message string, size int) error {
	out, err := EncodeMessage(int(MessageType_RESPONSE), nil, nil, nil, nil, &status, &message, &size, nil)
	if err != nil {
		log.Printf("EncodeMessage fails in SendResponse\n")
		return err
	}
	send := string(out)
	log.Printf("filehandler: SendResponse sending %s %s %d\n", status, message, len(send))
	n, err := ms.WriteString(send)
	if err != nil {
		log.Printf("filehandler: SendResponse Writestring error %d\n", n, err)
		return err
	}
	return nil
}

func SendProtocolMessage(ms *util.MessageStream, size int, buf []byte) error {
	log.Printf("filehandler: SendProtocolMessage\n")
	out, err := EncodeMessage(int(MessageType_PROTOCOL_RESPONSE), nil, nil, nil, nil, nil, nil, &size, buf)
	if err != nil {
		log.Printf("EncodeMessage fails in SendProtocolMessage\n")
		return err
	}
	send := string(out)
	n, err := ms.WriteString(send)
	if err != nil {
		log.Printf("filehandler: SendProtocolMessage Writestring error %d\n", n, err)
		return err
	}
	return nil
}

func GetProtocolMessage(ms *util.MessageStream) ([]byte, error) {
	log.Printf("filehandler: GetProtocolMessage\n")
	strbytes, err := ms.ReadString()
	if err != nil {
		return nil, err
	}
	log.Printf("GetProtocolMessage read %d bytes\n", len(strbytes))
	theType, _, _, _, _, _, _, _, out, err := DecodeMessage([]byte(strbytes))
	if err != nil {
		log.Printf("DecodeMessage error in GetProtocolMessage\n")
		return nil, err
	}
	if *theType != int(MessageType_PROTOCOL_RESPONSE) {
		return nil, errors.New("Wrong message type")
	}
	return out, nil
}

func AuthenticatePrincipal(m *ResourceMaster, ms *util.MessageStream) (bool, []byte) {
	log.Printf("AuthenticatePrincipal\n")
	offeredCert, err := GetProtocolMessage(ms)
	if err != nil {
		log.Printf("cant GetProtocolMessage in AuthenticatePrincipal % x\n", offeredCert)
	}
	log.Printf("AuthenticatePrincipal: got offered cert\n")
	nonce := make([]byte, SizeofNonce)
	_, err = rand.Read(nonce)
	if err != nil {
		log.Printf("Rand error in AuthenticatePrincipal\n")
	}
	log.Printf("nonce: % x\n", nonce)
	SendProtocolMessage(ms, len(nonce), nonce)
	log.Printf("AuthenticatePrincipal: sent nonce\n")
	signedRand, err := GetProtocolMessage(ms)
	if err != nil {
		log.Printf("cant GetProtocolMessage in AuthenticatePrincipal\n")
	}
	log.Printf("AuthenticatePrincipal: got signed nonce % x\n", signedRand)
	// Decrypt nonce
	cert, err := x509.ParseCertificate(offeredCert)
	if err != nil {
		log.Printf("cant Parse Certificate in AuthenticatePrincipal\n")
	}
	v, err := tao.FromX509(cert)
	if err != nil {
		log.Printf("cant get verifier from x509 AuthenticatePrincipal\n")
	}
	ok, err := v.Verify(nonce, ChallengeContext, signedRand)
	if err != nil {
		return false, nil
	}
	if ok {
		var opts x509.VerifyOptions
		roots := x509.NewCertPool()
		if !MyProgramPolicy.Initialized {
			log.Printf("MyProgramPolicy not initialized")
			return false, nil
		}
		policyCert, err := x509.ParseCertificate(MyProgramPolicy.ThePolicyCert)
		if err != nil || policyCert == nil {
			log.Printf("Can't parse policy cert")
			return false, nil
		}
		roots.AddCert(policyCert)
		opts.Roots = roots
		// Now check cert chain
		chains, err := cert.Verify(opts)
		if chains == nil || err != nil {
			log.Printf("Can't validate cert chain to policy")
			return false, nil
		}
		log.Printf("Cert chain for challenge verified\n")
	}
	if ok {
		log.Printf("nonce verified\n")
	} else {
		log.Printf("nonce did not verified\n")
	}
	var status string
	if ok {
		status = "succeeded"
	} else {
		status = "failed"
	}
	msg := ""
	SendResponse(ms, status, msg, 0)
	return ok, offeredCert
}

func AuthenticatePrincipalRequest(ms *util.MessageStream, key *tao.Keys, derCert []byte) bool {
	log.Printf("AuthenticatePrincipalRequest\n")
	// Format request
	subject := "jlm"
	action := "authenticateprincipal"
	owner := "jlm"
	message, err := EncodeMessage(int(MessageType_REQUEST), &subject, &action, &subject, &owner,
		nil, nil, nil, nil)
	if err != nil {
		log.Printf("AuthenticatePrincipalRequest couldnt build request\n")
		return false
	}
	log.Printf("AuthenticatePrincipalRequest request %d, ", len(message))
	log.Printf("\n")
	_, err = ms.WriteString(string(message))
	if err != nil {
		log.Printf("AuthenticatePrincipalRequest couldnt write challenge\n")
		return false
	}
	log.Printf("AuthenticatePrincipalRequest: sent request\n")
	SendProtocolMessage(ms, len(derCert), derCert)
	log.Printf("AuthenticatePrincipalRequest: sent cert\n")
	nonce, err := GetProtocolMessage(ms)
	if err != nil {
		log.Printf("cant GetProtocolMessage in AuthenticatePrincipalRequest\n")
		return false
	}
	log.Printf("AuthenticatePrincipalRequest: got nonce\n")
	// Encrypt nonce
	signedBlob, err := key.SigningKey.Sign(nonce, "fileproxy-challenge")
	if err != nil {
		log.Printf("AuthenticatePrincipalRequest: cant sign\n")
	}
	SendProtocolMessage(ms, len(signedBlob), signedBlob)
	log.Printf("AuthenticatePrincipalRequest: sent signed\n")
	status, _, _, err := GetResponse(ms)
	if err != nil {
		log.Printf("cant GetResponse in AuthenticatePrincipalRequest\n")
		return false
	}
	log.Printf("AuthenticatePrincipalRequest: status of response: %s\n", *status)
	return true
}

func readRequest(m *ResourceMaster, ms *util.MessageStream, resourcename string) error {
	log.Printf("filehandler: readRequest\n")
	rInfo, _ := m.Find(resourcename)
	if rInfo == nil {
		SendResponse(ms, "failed", "resource does not exist", 0)
		return nil
	}
	status := "succeeded"
	SendResponse(ms, status, "", 0)
	return SendFile(ms, m.BaseDirectory, resourcename, nil)
}

func writeRequest(m *ResourceMaster, ms *util.MessageStream, resourcename string) error {
	log.Printf("filehandler: writeRequest\n")
	rInfo, _ := m.Find(resourcename)
	if rInfo == nil {
		SendResponse(ms, "failed", "resource does not exist", 0)
		return nil
	}
	status := "succeeded"
	SendResponse(ms, status, "", 0)
	return GetFile(ms, m.BaseDirectory, resourcename, nil)
}

func createRequest(m *ResourceMaster, ms *util.MessageStream,
	resourcename string, owner string) error {
	log.Printf("filehandler: createRequest\n")
	rInfo, _ := m.Find(resourcename)
	if rInfo != nil {
		SendResponse(ms, "failed", "resource exists", 0)
		return nil
	}
	// Is it authorized
	rInfo, _ = m.Insert(m.BaseDirectory, resourcename, owner)
	if rInfo == nil {
		SendResponse(ms, "failed", "cant insert resource", 0)
		return nil
	}
	rInfo.PrintResourceInfo()
	status := "succeeded"
	SendResponse(ms, status, "", 0)
	return nil
}

func newruleRequest(m *ResourceMaster, ms *util.MessageStream,
	rule string, signerCert []byte) error {

	log.Printf("filehandler, newruleRequest, rule: %s\n", rule)
	signerName := PrincipalNameFromDERCert(signerCert)
	if signerName == nil {
		log.Printf("filehanadler, newruleRequest: cant get name from cert\n")
		return nil
	}
	log.Printf("filehandler, newRuleRequest: %s\n", *signerName)
	prin, err := m.FindPrincipal(*signerName)
	if prin != nil {
		log.Printf("filehanadler, newRuleRequest: found principal, %s %s\n", prin.Name, prin.Status)
	}
	if err != nil || prin == nil || !bytes.Equal(prin.Der, signerCert) {
		SendResponse(ms, "failed", "cert doesn't match", 0)
		return nil
	}
	// Check a signature?
	m.Guard.AddRule(rule)
	SendResponse(ms, "succeeded", "", 0)
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

func (m *ResourceMaster) certToAuthenticatedName(subjectCert []byte) *string {
	if subjectCert == nil {
		return nil
	}
	var subjectName *string
	subjectName = nil
	subjectName = PrincipalNameFromDERCert([]byte(subjectCert))
	if subjectName == nil {
		log.Printf("filehanadler, certToAuthenticatedName: cant get name from cert\n")
		return nil
	}
	log.Printf("filehandler, certToAuthenticatedName: %s\n", *subjectName)
	prin, err := m.FindPrincipal(*subjectName)
	if prin != nil {
		log.Printf("filehanadler, certToAuthenticatedName: found principal, %s %s\n", prin.Name, prin.Status)
	}
	if err != nil || prin == nil || bytes.Equal(prin.Der, []byte(*subjectName)) {
		return nil
	}
	return subjectName
}

// First return value is terminate flag
func (m *ResourceMaster) HandleServiceRequest(ms *util.MessageStream, request []byte) (bool, error) {
	log.Printf("filehandler: HandleServiceRequest\n")
	subject, action, resourcename, owner, err := DecodeRequest(request)
	if err != nil {
		return false, err
	}
	log.Printf("HandleServiceRequest\n")
	if owner != nil {
		PrintRequest([]byte(*subject), action, resourcename, []byte(*owner))
	} else {
		PrintRequest([]byte(*subject), action, resourcename, nil)
	}

	if *action == "authenticateprincipal" {
		ok, ownerCert := AuthenticatePrincipal(m, ms)
		if ok {
			ownerName := PrincipalNameFromDERCert([]byte(ownerCert))
			if ownerName == nil {
				log.Printf("can't get ownername after AuthenticatePrincipal\n")
				return false, nil
			}
			log.Printf("filehandler inserting %s %s\n", *ownerName, "authenticated")
			_, err = m.InsertPrincipal(*ownerName, []byte(ownerCert), "authenticated")
			if err != nil {
				log.Printf("cant insert principal name in file\n")
				return false, errors.New("cant insert principal name in file")
			}
			log.Printf("HandleServiceRequest: Added %s to Principal table\n", *ownerName)
			return false, nil
		} else {
			return false, errors.New("AuthenticatePrincipal failed")
		}
	} else if *action == "sendrule" {
		err = newruleRequest(m, ms, *resourcename /* rule */, []byte(*owner))
		if err != nil {
			return false, errors.New("Cant construct newrulequest")
		}
		return false, nil
	}

	// Replace owner and subject with name
	var ownerName *string
	ownerName = nil
	if owner != nil {
		ownerName = m.certToAuthenticatedName([]byte(*owner))
		if ownerName == nil {
			status := "failed"
			message := "unknown owner specified"
			SendResponse(ms, status, message, 0)
			return false, errors.New("unauthenticated principal")
		}
	}
	var subjectName *string
	subjectName = nil
	if subject != nil {
		subjectName = m.certToAuthenticatedName([]byte(*subject))
		if subjectName == nil {
			status := "failed"
			message := "unknown owner specified"
			SendResponse(ms, status, message, 0)
			return false, errors.New("unauthenticated principal")
		}
	}
	if subjectName != nil {
		log.Printf("filehandler, HandleRequest, Subjectname: %s\n", *subjectName)
	}
	if ownerName != nil {
		log.Printf("filehandler, HandleRequest, Ownername: %s\n", *ownerName)
	}

	// Is it authorized?
	var ok bool
	if *action == "create" {
		addResource(*ownerName, *resourcename, m.Guard)
		fileserverSubject := "fileserver"
		query := makeQuery(fileserverSubject, *action, *resourcename)
		if query == nil {
			log.Printf("bad query")
		}
		ok = m.Query(*query)
		if !ok {
			m.PrintAllPolicy()
		}
	} else if *action == "getfile" {
		query := makeQuery(*subjectName, *action, *resourcename)
		if query == nil {
			log.Printf("bad query")
		}
		ok = m.Query(*query)
	} else if *action == "sendfile" {
		query := makeQuery(*subjectName, *action, *resourcename)
		if query == nil {
			log.Printf("bad query")
		}
		ok = m.Query(*query)
	} else {
		ok = false
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
	log.Printf("filehandler: InitMaster\n")
	m.Policy = policy
	m.AdditionalPolicy = additional_policy
	m.NumResources = 0
	m.NumPrincipals = 0
	m.BaseDirectory = filepath
	m.InitGuard(masterInfoDir + "rules")
	m.PrintAllPolicy()
	return nil
}

func (m *ResourceMaster) SaveMaster(masterInfoDir string) error {
	log.Printf("filehandler: SaveMaster\n")
	err := m.SaveResourceData(masterInfoDir+"masterFile", masterInfoDir+"resourceFile",
		masterInfoDir+"resourceFile", masterInfoDir+"ruleFile")
	if err != nil {
		log.Printf("filehandler: cant m.SaveResourceData\n")
		return err
	}
	return m.SaveRules(masterInfoDir + "rules")
}
