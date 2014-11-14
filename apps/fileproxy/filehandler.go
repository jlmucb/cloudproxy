// Copyright (c) 2014, Google, Inc. .  All rights reserved.
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

type PrincipalInfo struct {
	Name   string
	Der    []byte
	Status string
}

type ResourceMaster struct {
	ProgramName      string
	Guard            tao.Guard
	BaseDirectory    string
	NumResources     int
	ResourceArray    []ResourceInfo
	NumPrincipals    int
	PrincipalArray   []PrincipalInfo
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
		log.Printf("Couldn't delegate operation '%s' on '%s' from '%s' to '%s': %s\n", op, res, owner, delegate, err)
	}
}

func redelegateResource(owner, delegate, op, res string, g tao.Guard) {
	if err := g.AddRule("Delegate(\"" + owner + "\", \"" + delegate + "\", \"delegate\", \"" + op + "\", \"" + res + "\")"); err != nil {
		log.Printf("Couldn't redelegate operation '%s' on '%s' from '%s' to '%s': %s\n", op, res, owner, delegate, err)
	}
}

func addResource(creator, resource string, g tao.Guard) error {
	if err := g.AddRule("Resource(\"" + resource + "\")"); err != nil {
		return errors.New("Can't add resource in rules\n")
	}
	if err := g.AddRule("Creator(\"" + creator + "\", \"" + resource + "\")"); err != nil {
		return errors.New("Can't add creator in rules\n")
	}
	return nil
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

func (m *ResourceMaster) FindResource(resourcename string) (*ResourceInfo, error) {
	for i := range m.ResourceArray {
		if m.ResourceArray[i].ResourceName == resourcename {
			return &m.ResourceArray[i], nil
		}
	}
	return nil, nil
}

func (m *ResourceMaster) InsertResource(path string, resourcename string, owner string) (*ResourceInfo, error) {
	found, err := m.FindResource(resourcename)
	if err != nil {
		return nil, err
	}
	if found != nil {
		return found, nil
	}
	if len(m.ResourceArray) >= cap(m.ResourceArray) {
		t := make([]ResourceInfo, 2*cap(m.ResourceArray))
		copy(t, m.ResourceArray)
		m.ResourceArray = t
	}
	m.ResourceArray = m.ResourceArray[0 : len(m.ResourceArray)+1]
	n := len(m.ResourceArray) - 1
	m.ResourceArray[n].ResourceName = resourcename
	m.ResourceArray[n].ResourceType = "file"
	m.ResourceArray[n].ResourceStatus = "created"
	m.ResourceArray[n].ResourceLocation = path + resourcename
	m.ResourceArray[n].ResourceOwner = owner
	return &m.ResourceArray[n], nil
}

func (m *ResourceMaster) FindPrincipal(name string) (*PrincipalInfo, error) {
	for i := range m.PrincipalArray {
		if m.PrincipalArray[i].Name == name {
			return &m.PrincipalArray[i], nil
		}
	}
	return nil, nil
}

func (m *ResourceMaster) InsertPrincipal(name string, cert []byte, authStatus string) (*PrincipalInfo, error) {
	found, err := m.FindPrincipal(name)
	if err != nil {
		return nil, err
	}
	if found != nil {
		return found, nil
	}
	if len(m.PrincipalArray) >= cap(m.PrincipalArray) {
		t := make([]PrincipalInfo, 2*cap(m.PrincipalArray))
		copy(t, m.PrincipalArray)
		m.PrincipalArray = t
	}
	m.PrincipalArray = m.PrincipalArray[0 : len(m.PrincipalArray)+1]
	n := len(m.PrincipalArray) - 1
	m.PrincipalArray[n].Name = name
	m.PrincipalArray[n].Der = cert
	m.PrincipalArray[n].Status = authStatus
	return &m.PrincipalArray[n], nil
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
		for i := range m.ResourceArray {
			m.ResourceArray[i].PrintResourceInfo()
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

func (p *PrincipalInfo) EncodePrincipal() ([]byte, error) {
	log.Printf("filehandler: encodePrincipalInfo\n")
	protoMessage := new(FPPrincipalInfo)
	protoMessage.PrincipalName = proto.String(p.Name)
	protoMessage.PrincipalStatus = proto.String(p.Status)
	protoMessage.PrincipalCert = proto.String(string(p.Der))
	out, err := proto.Marshal(protoMessage)
	return out, err
}

func (p *PrincipalInfo) DecodePrincipal(in []byte) error {
	log.Printf("filehandler: DecodePrincipalInfo\n")
	rMessage := new(FPPrincipalInfo)
	_ = proto.Unmarshal(in, rMessage)
	p.Name = *rMessage.PrincipalName
	p.Status = *rMessage.PrincipalStatus
	p.Der = []byte(*rMessage.PrincipalCert)
	return nil
}

func (p *PrincipalInfo) PrintPrincipal() {
	log.Printf("Principal name: %s\n", p.Name)
	log.Printf("Principal status: %s\n", p.Status)
	log.Printf("Principal cert: %s\n", p.Der)
	log.Printf("\n")
}

func (m *ResourceMaster) PrintAllPolicy() {
	for i := range m.Policy {
		log.Printf("Rule: %s\n", m.Policy[i])
	}
	for i := range m.AdditionalPolicy {
		log.Printf("Rule: %s\n", m.AdditionalPolicy[i])
	}
}

func (m *ResourceMaster) InitGuard(rulefile string) error {
	log.Printf("filehandler: InitGuard\n")
	m.Guard = tao.NewTemporaryDatalogGuard()
	for i := range m.Policy {
		if err := m.Guard.AddRule(m.Policy[i]); err != nil {
			return errors.New("Couldn't add rule in InitGuard")
		}
	}

	for i := range m.AdditionalPolicy {
		if err := m.Guard.AddRule(m.AdditionalPolicy[i]); err != nil {
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
	for i := range m.ResourceArray {
		resourceRecord, _ := rs.ReadString()
		_ = m.ResourceArray[i].DecodeResourceInfo([]byte(resourceRecord))
		log.Printf("resourceRecord size: %d\n", len(resourceRecord))
	}
	fo.Close()

	// Read principals
	fo, _ = os.Open(principalFile)
	ps := util.NewMessageStream(fo)
	for i := range m.PrincipalArray {
		principalRecord, _ := ps.ReadString()
		_ = m.PrincipalArray[i].DecodePrincipal([]byte(principalRecord))
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
	for i := range m.ResourceArray {
		resourceRecord, _ := m.ResourceArray[i].EncodeResourceInfo()
		log.Printf("resourceRecord size: %d\n", len(resourceRecord))
		_, _ = rs.WriteString(string(resourceRecord))
	}
	fo.Close()
	// Save principals
	fo, _ = os.Create(principalFile)
	ps := util.NewMessageStream(fo)
	for i := range m.PrincipalArray {
		principalRecord, _ := m.PrincipalArray[i].EncodePrincipal()
		log.Printf("principalRecord size: %d\n", len(principalRecord))
		_, _ = ps.WriteString(string(principalRecord))
	}
	fo.Close()

	// Save rules
	_ = m.SaveRules(ruleFile)
	return nil
}

func AuthenticatePrincipal(m *ResourceMaster, ms *util.MessageStream, programPolicyObject *ProgramPolicy) (bool, []byte) {
	log.Printf("AuthenticatePrincipal\n")
	offeredCert, err := GetProtocolMessage(ms)
	if err != nil {
		log.Printf("cant GetProtocolMessage in AuthenticatePrincipal % x\n", offeredCert)
	}
	nonce := make([]byte, SizeofNonce)
	_, err = rand.Read(nonce)
	if err != nil {
		log.Printf("Rand error in AuthenticatePrincipal\n")
	}
	SendProtocolMessage(ms, len(nonce), nonce)
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
		if !programPolicyObject.Initialized {
			log.Printf("MyProgramPolicy not initialized")
			return false, nil
		}
		policyCert, err := x509.ParseCertificate(programPolicyObject.ThePolicyCert)
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
	subject := string(derCert)
	action := "authenticateprincipal"
	err := SendRequest(ms, &subject, &action, &subject, nil)
	if err != nil {
		log.Printf("AuthenticatePrincipalRequest: couldn't send request\n")
	}
	SendProtocolMessage(ms, len(derCert), derCert)
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

func readRequest(m *ResourceMaster, ms *util.MessageStream, resourcename string, symKey []byte) error {
	log.Printf("filehandler: readRequest\n")
	rInfo, _ := m.FindResource(resourcename)
	if rInfo == nil {
		SendResponse(ms, "failed", "resource does not exist", 0)
		return nil
	}
	status := "succeeded"
	SendResponse(ms, status, "", 0)
	return SendFile(ms, m.BaseDirectory, resourcename, symKey)
}

func writeRequest(m *ResourceMaster, ms *util.MessageStream, resourcename string, symKey []byte) error {
	log.Printf("filehandler: writeRequest\n")
	rInfo, _ := m.FindResource(resourcename)
	if rInfo == nil {
		SendResponse(ms, "failed", "resource does not exist", 0)
		return nil
	}
	status := "succeeded"
	SendResponse(ms, status, "", 0)
	return GetFile(ms, m.BaseDirectory, resourcename, symKey)
}

func createRequest(m *ResourceMaster, ms *util.MessageStream,
	resourcename string, owner string) error {
	log.Printf("filehandler: createRequest\n")
	rInfo, _ := m.FindResource(resourcename)
	if rInfo != nil {
		SendResponse(ms, "failed", "resource exists", 0)
		return nil
	}
	rInfo, _ = m.InsertResource(m.BaseDirectory, resourcename, owner)
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
		log.Printf("filehandler, newruleRequest: cant get name from cert\n")
		return nil
	}
	prin, err := m.FindPrincipal(*signerName)
	if prin != nil {
		log.Printf("filehandler, newRuleRequest: found principal, %s %s\n", prin.Name, prin.Status)
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
		log.Printf("filehandler, certToAuthenticatedName: cant get name from cert\n")
		return nil
	}
	prin, err := m.FindPrincipal(*subjectName)
	if prin != nil {
		log.Printf("filehandler, certToAuthenticatedName: found principal, %s %s\n", prin.Name, prin.Status)
	}
	if err != nil || prin == nil || bytes.Equal(prin.Der, []byte(*subjectName)) {
		return nil
	}
	return subjectName
}

// First return value is terminate flag
func (m *ResourceMaster) HandleServiceRequest(ms *util.MessageStream, programPolicyObject *ProgramPolicy, clientProgramName string, request []byte) (bool, error) {
	log.Printf("filehandler: HandleServiceRequest\n")

	fpMessage := new(FPMessage)
	err := proto.Unmarshal(request, fpMessage)
	if err != nil {
		return false, errors.New("HandleService can't unmarshal request")
	}
	if fpMessage.MessageType == nil {
		return false, errors.New("HandleService: no message type")
	}
	switch MessageType(*fpMessage.MessageType) {
	default:
		return false, errors.New("HandleService does not get MessageType_REQUEST")
	case MessageType_REQUEST:
	}
	action := fpMessage.ActionName
	if action == nil {
		SendResponse(ms, "failed", "", 0)
		return false, errors.New("no action")
	}
	subject := fpMessage.SubjectName
	resourceName := fpMessage.ResourceName
	owner := fpMessage.ResourceOwner

	log.Printf("HandleServiceRequest %s\n", *action)

	switch *action {
	case "authenticateprincipal":
		ok, ownerCert := AuthenticatePrincipal(m, ms, programPolicyObject)
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
	case "sendrule":
		log.Printf("filehandler sendrule %s\n", *resourceName)
		if resourceName == nil || owner == nil {
			SendResponse(ms, "failed", "no ownername or resourcename", 0)
			return false, nil
		}
		err = newruleRequest(m, ms, *resourceName /* rule */, []byte(*owner))
		if err != nil {
			return false, errors.New("Can't construct newrulequest")
		}
		return false, nil
	default:
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
	switch *action {
	case "create":
		if ownerName == nil {
			SendResponse(ms, "failed", "no owner name", 0)
			return false, nil
		}
		addResource(*ownerName, *resourceName, m.Guard)
		fileserverSubject := "fileserver"
		query := makeQuery(fileserverSubject, *action, *resourceName)
		if query == nil {
			log.Printf("bad query")
		}
		ok = m.Query(*query)

	case "getfile":
		if subjectName == nil || resourceName == nil {
			SendResponse(ms, "failed", "no subjectname or resourcename", 0)
			return false, nil
		}
		query := makeQuery(*subjectName, *action, *resourceName)
		if query == nil {
			log.Printf("bad query")
		}
		ok = m.Query(*query)
	case "sendfile":
		if subjectName == nil || resourceName == nil {
			SendResponse(ms, "failed", "no subjectname or resourcename", 0)
			return false, nil
		}
		query := makeQuery(*subjectName, *action, *resourceName)
		if query == nil {
			log.Printf("bad query")
		}
		ok = m.Query(*query)
	default:
		ok = false
	}
	if ok == false {
		SendResponse(ms, "failed", "unauthorized", 0)
		return false, nil
	}

	switch *action {
	case "create":
		if resourceName == nil || ownerName == nil {
			return false, errors.New("Nil parameters for createRequest")
		}
		err := createRequest(m, ms, *resourceName, *ownerName)
		return false, err
	case "delete":
		err := deleteRequest(m, ms, *resourceName)
		return false, err
	case "getfile":
		if programPolicyObject.MySymKeys == nil {
			log.Printf("HandleFileRequest, getfile keys nil\n")
		} else {
			log.Printf("HandleFileRequest, getfile keys NOT nil\n")
		}
		err := readRequest(m, ms, *resourceName, programPolicyObject.MySymKeys)
		return false, err
	case "sendfile":
		if programPolicyObject.MySymKeys == nil {
			log.Printf("HandleFileRequest, sendfile keys nil\n")
		} else {
			log.Printf("HandleFileRequest, sendfile keys NOT nil\n")
		}
		err := writeRequest(m, ms, *resourceName, programPolicyObject.MySymKeys)
		return false, err
	case "terminate":
		return true, nil
	default:
		SendResponse(ms, "failed", "unsupported action", 0)
		return false, errors.New("unsupported action")
	}
}

func (m *ResourceMaster) InitMaster(filepath string, masterInfoDir string, prin string) error {
	log.Printf("filehandler: InitMaster\n")
	m.Policy = policy
	m.AdditionalPolicy = additional_policy
	m.ResourceArray = make([]ResourceInfo, 100)
	m.ResourceArray = m.ResourceArray[0:0]
	m.PrincipalArray = make([]PrincipalInfo, 100)
	m.PrincipalArray = m.PrincipalArray[0:0]
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
