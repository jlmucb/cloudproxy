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
	//"crypto/x509"
	//"errors"
	//"io/ioutil"
	"flag"
	"fmt"
	//"net"
	"os"

	 tao "github.com/jlmucb/cloudproxy/tao"
	 "github.com/jlmucb/cloudproxy/tao/auth"
	// taonet "github.com/jlmucb/cloudproxy/tao/net"
	"github.com/jlmucb/cloudproxy/apps/fileproxy"
)

// Resource types: files, channels

type ResourceInfo struct {
	resourceName		string
	resourceType		string
	resourceLocation	string
	resourceSize		int
	resourceOwner		[]byte   // x509 cert
	dateCreated		string
	dateModified		string
	authenticatorType	string	 // sha hash usually
	authenticator		[][]byte
}


type ResourceMaster {
	program		auth.Prin
	guard		*tao.Guard
	baseDirectory	string
	resourceArray	[]ResourceInfo
	// Rules
};

func (m *ResourceMaster) Find(resourcename string) (*ResourceInfo, error){
	for i:=0; i< m.resourceArray.len();i++ {
		 if(m.resourceArray[i].resourceName==resourcename) {
			 return &m.resourceArray[i], nil
		 }
	}
	return nil, nil
}

func (m *ResourceMaster) Insert(resourcename string) (*ResourceInfo, error){
	found, err:=  Find(resourcename)
	return nil, errors.New("Resource exists")
}

// return: type, subject, action, resource, status, message, size, buf, error
func decodeMessage(in *FPMessage) (*int, *string,  *string, *string,
		      *string, *string,  *int,  *[]byte, error) {
	theType:= *in.message_type
	if(theType==REQUEST) {
		subject:= *in.subject_name
		action:= *in.action_name
		resourcename:= *in.resource_name
		return &theType, &subject, &action, &resourcename, nil,nil,nil,nil,nil
	else if (theType==RESPONSE) {
		status:= *in.status_of_request
		message:= *in.message_from_request
		return &theType, nil,nil,nil, &status, &message, nil,nil,nil
	}
	else if (theType==FILE_NEXT) {
		size:= *in.size_buffer
		out:= *in.the_buffer
		return &theType, nil,nil,nil, nil,nil, &size, &out, nil
	}
	else if (theType==FILE_LAST) {
		size:= *in.size_buffer
		out:= *in.the_buffer
		return &theType, nil,nil,nil, nil,nil, &size, &out, nil
	}
	else {
		return nil,nil,nil,nil,nil,nil,nil,nil errors.New("unknown message type\n")
	}
}

func encodeMessage(type int, subject *string,  action *string, resourcename *string,
		   status *string, message *string,  size int,  buf []byte) (*FPMessage, error) {
	protoMessage:=  new(FPMessage)
	protoMessage.message_type= proto.Int(type)
	if(type==REQUEST) {
		protoMessage.subject_name= proto.String(*subject)
		protoMessage.action_name= proto.String(*action)
		protoMessage.resource_name= proto.String(*resourcename)
	else if (type==RESPONSE) {
		protoMessage.status_of_request= proto.String(*status)
		protoMessage.message_from_request= proto.String(*message)
	}
	else if (type==FILE_NEXT) {
		protoMessage.size_buffer= proto.Int(size)
		protoMessage.the_buffer= proto.Bytes(*buf)
	}
	else if (type==FILE_LAST) {
		protoMessage.size_buffer= proto.Int(size)
		protoMessage.the_buffer= proto.Bytes(*buf)
	}
	else {
		return errors.New("unknown message type\n")
	}
}

func (m *ResourceMaster) Delete(resourceName string) error {
	return nil // not implemented
}

func (m *ResourceMaster) encodeMaster() (string, error){
}

func (m *ResourceMaster) decodeMaster(record string) error {
}

func (m *ResourceInfo) encodeResourceInfo() (string, error){
}

func (m *ResourceInfo) decodeResourceInfo(record string) error {
}

func (r *ResourceInfo) PrintResourceInfo() {
	fmt.Printf("Resource name: %s\n", r.resourceName)
	fmt.Printf("Resource type: %s\n" , r.resourceType)
	fmt.Printf("Resource location: %s\n" , r.resourceLocation)
	fmt.Printf("Resource size: %d\n" , r.resourceSize)
	fmt.Printf("Resource creation date: %s\n" , r.dateCreated)
	fmt.Printf("Resource modified date: %s\n" , r.dateModified)
	fmt.Printf("\n")
}

func (m *ResourceMaster) PrintMaster(bool printResources) {
	fmt.Printf("Program principal: %s\n", m.program)
	fmt.Printf("Base Directory: %s\n", m.baseDirectory)
	fmt.Printf("%d resources\n", m.resourceArray.len())
	if(printResources) {
		for i:=0; i< m.resourceArray.len();i++ {
			 m.resourceArray[i].PrintResourceInfo() 
		}
	}
}

func (r ResourceMaster*)  MarshalResourceMaster() (string, err) {
}

func UnmarshalMarshalResourceMaster(in string) (*ResourceMaster, err) {
}

func (r ResourceInfo*)  MarshalResourceInfo() (string, err) {
}

func UnmarshalMarshalResourceInfo(in string) (*ResourceInfo, err) {
}

// Policy
//	actions are: read, write, create, delete, add-own, delete-own, delegate-read, delegate-write, 
//		     delegate-create, delegate-delete, delegate-add-own, delegate-delete-own
//
//	fileserver owns everything and can add any rule
//		forall resource: IsPrincipal(fileserver) --> IsOwner(fileserver, resource)
//		forall rule: IsPrincipal(fileserver) --> CanAddRule(rule)
//	Creators are owners
//		forall user, resource: IsCreator(user, resource) --> IsOwner(user, resource)
//	Owners can perform all actions
//		forall owner, action, resource: IsOwner(owner, resource) and IsAction(action) -->
//			Can(action, owner, resource)
//	Principals have namespace where they can create things
//		forall name, resourcename: IsPrincipal(name) --> Can(create, /resourcepath/NAME/resourcename)
//	Basic Delegation
//		forall user, delegate, resourcename: Can(user, delegate-ACTION, resource) and 
//			Says(user, delegate, ACTION, resourcename) --> Can(ACTION, delegate, resource)
//	Redelegation
//		forall user, delegate, resourcename: Can(user, delegate-ACTION, resource) and 
//			Says(user, delegate, delegate-ACTION, resourcename) --> 
//			Can(delegate-ACTION, delegate, resource)
//	Adding rules:
//		forall user, delegate-ACTION,resource: Can(user, delegate-ACTION, delegate, resource) --> 
//			CanAddRule("user says delegate Can(ACTION,user,resource)") and
//			CanAddRule("user says delegate Can(delegate-ACTION,user,resource)")
//
// It might be cleaner to write if you add some custom predicates in datalog to handle the connection between 
// ACTION and delegate-ACTION, but I believe it can be made to work without that.
// the auth language already understands delegation, so you shouldn't need to encode it directly in your rules. 
// It has a says type and it has a speaksfor.  
// The "Can" predicate is represented in the Guard terminology by Authorized(name, op, args).

func (m *ResourceMaster) InitGuard(g *tao.Guard, rulefile string) error {
	//fileGuard := tao.NewTemporaryDatalogGuard()
	// for now, liberal guard
	*m.g=  LiberalGuard
	// no need for rules
	return nil
}

func (m *ResourceMaster) SaveRules(g *tao.Guard, rulefile string) error {
	// no need for rules
	return nil
}

func (m *ResourceMaster) GetResourceData(masterInfoFile string,  resourceInfoArrayFile string) error {
	// read master info
	// decrypt it
	// read resourceinfos
	// decrypt it

	// read rule file
	// decrypt it
}

func (m *ResourceMaster) SaveResourceData(masterInfoFile string,  resourceInfoArrayFile string, ruleFile string) error {
	// encrypt master info
	// write master info
	// encrypt fileinfos
	// write fileinfos
	// encrypt rules
	// write rules
}

// return values: subject, action, resourcename, action-data error
func decodeRequest(request string) (*string, *string, *string, *string, error) {
	return nil,nil,nil,nil, errors.New("Cant decode request")
}

func encodeResponse(status string, message string, size int) {
}

func sendResponse(conn net.Conn, status string, message string, size int) {
}

func readRequest(conn net.Conn, resourcename string) {
}

func writeRequest(conn net.Conn, resourcename string) {
}

func createRequest(conn net.Conn, subject string, resourcename string) {
}

func deleteRequest(conn net.Conn, resourcename string) {
}

func addRuleRequest(conn net.Conn, resourcename string) {
}

func addOwnerRequest(conn net.Conn, resourcename string) {
}

func deleteOwnerRequest(conn net.Conn, resourcename string) {
}

// first return value is terminate flag
func (m *ResourceMaster) HandleServiceRequest(conn net.Conn, request string) (bool, error) {
	// decode request
	subject, action, resourcename, data, err:= decodeRequest(request)

	// is it authorized?
	var status string
	var message string
	ok:= m.guard.IsAuthorized(subject, action, resourcename)
	if ok == nil {
		status= "failed"
		message= "unauthorize"
		sendErrorResponse(status, message);
	}
}

func (m *ResourceMaster) InitMaster(masterInfoDir string, prin tao.Prin)  error {
	m.GetResourceData(masterInfoDir+"masterinfo",  masterInfoDir+"resources")
	m.InitGuard(m.guard, masterInfoDir+"rules") {
}

func (m *ResourceMaster) SaveMaster(masterInfoDir string)  error {
	err:= m.SaveResourceData(masterInfoDir+"masterinfo",  masterInfoDir+"resources")
	if err!=nil {
		fmt.Printf("cant m.SaveResourceData\n")
		return err
	}
	return m.SaveRules(m.guard, masterInfoDir+"rules")
}

