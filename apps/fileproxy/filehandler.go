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

func (m *ResourceMaster) Find(resourcename string) (*ResourceInfo, error) {
	for i:=0; i< m.resourceArray.len();i++ {
		 if(m.resourceArray[i].resourceName==resourcename) {
			 return &m.resourceArray[i], nil
		 }
	}
	return nil, nil
}

func (m *ResourceMaster) Insert(path, string, resourcename string, owner []byte) (*ResourceInfo, error) {
	found, err:=  Find(resourcename)
	if(found!=nil)
		return found, nil
	n:=  resourceArray.len()
	resourceArray[n]=  new  ResourceInfo()
	resourceArray[n].resource_name= resourcename
	resourceArray[n].resource_type= "file"
	resourceArray[n].resource_status= "created"
	resourceArray[n].resource_location=  path+resourcename
	resourceArray[n].resource_owner=  owner
}

// return: type, subject, action, resource, owner, status, message, size_buf, buf, error
func decodeMessage(in []byte) (*int, *string,  *string, *string, *[]byte,
		      *string, *string,  *int,  *[]byte, error) {
	fpMessage, err:= proto.Unmarshal(in)
	theType:= *fpMessage.message_type
	if(theType==REQUEST) {
		subject:= *fpMessage.subject_name
		action:= *fpMessage.action_name
		resourcename:= *fpMessage.resource_name
		// TODO: check to see if its nil
		owner:=  *fpMessage.resource_owner
		return &theType, &subject, &action, &resourcename, &owner, nil,nil,nil,nil,nil
	else if (theType==RESPONSE) {
		status:= *fpMessage.status_of_request
		message:= *fpMessage.message_from_request
		return &theType, nil,nil,nil, nil, &status, &message, nil,nil,nil
	}
	else if (theType==FILE_NEXT || theType==FILE_LAST) {
		size:= *fpMessage.size_buffer
		out:= *fpMessage.the_buffer
		return &theType, nil, nil,nil,nil, nil,nil, &size, &out, nil
	} else {
		return nil,nil,nil,nil,nil,nil,nil,nil errors.New("unknown message type\n")
	}
}

func encodeMessage(theType int, subject *string,  action *string, resourcename *string, owner *[]byte,
		   status *string, message *string,  size int,  buf []byte) ([]byte, error) {
	protoMessage:=  new(FPMessage)
	protoMessage.message_type= proto.Int(theType)
	if(theType==REQUEST) {
		protoMessage.subject_name= proto.String(*subject)
		protoMessage.action_name= proto.String(*action)
		protoMessage.resource_name= proto.String(*resourcename)
		protoMessage.resource_owner= proto.Bytes(*owner)
	else if (theType==RESPONSE) {
		protoMessage.status_of_request= proto.String(*status)
		protoMessage.message_from_request= proto.String(*message)
	}
	else if (theType==FILE_NEXT) {
		protoMessage.size_buffer= proto.Int(size)
		protoMessage.the_buffer= proto.Bytes(*buf)
	}
	else if (theType==FILE_LAST) {
		protoMessage.size_buffer= proto.Int(size)
		protoMessage.the_buffer= proto.Bytes(*buf)
	}
	else {
		return nil, errors.New("unknown message type\n")
	}
	out, err:=proto.Marshal(protoMessage)
	return out, err
}

func (m *ResourceMaster) Delete(resourceName string) error {
	return nil // not implemented
}

func (m *ResourceMaster) encodeMaster() ([]byte, error){
	protoMessage:=  new(FPResourceMaster)
	protoMessage.prin_name= proto.String(m.program);
	protoMessage.baseDirectory_name= proto.String(m.baseDirectory);
	protoMessage.num_fileinfos= proto.Int(m.resourceArray.len())
	out, err:= proto.Marshal(protoMessage)
	return out, err
}

func (m *ResourceMaster) decodeMaster(int*, in []byte) error {
	 rMessage:= proto.Unmarshal(in)
	 m.program= *rMessage.prin_name
	 m.baseDirectory= *rMessage.baseDirectory_name
	 size:=  *rMessage.num_fileinfos
	 return &size, nil
}

func (r *ResourceInfo) encodeResourceInfo() ([]byte, error){
	protoMessage:=  new(FPResourceInfo)
	protoMessage.resource_name= proto.String(r.resourceName);
	protoMessage.resource_type= proto.String(r.resourceType);
	protoMessage.resource_location= proto.String(r.resourceLocation);
	protoMessage.resource_size= proto.Int(r.resourceSize);
	protoMessage.resource_owner= proto.Bytes(r.resourceOwner);
	out, err:= proto.Marshal(protoMessage)
	return out, nil
}

func (m *ResourceInfo) decodeResourceInfo(in []byte) error {
	rMessage:= proto.Unmarshal(in)
	r.resourceName= *rMessage.resource_name
	r.resourceType= *rMessage.resource_type
	r.resourceLocation= *rMessage.resource_location
	r.resourceSize= *rMessage.resource_size
	r.resourceOwner= *rMessage.resource_owner
	return nil
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

// return values: subject, action, resourcename, size, error
func encodeRequest(subject string, action string, resourcename string, owner []byte) ([]byte, error) {
	out,err:= encodeMessage(REQUEST, subject,  action, resourcename, owner,
	                   nil, nil,  nil,  nil)
	return  out, err
}

// return values: subject, action, resourcename, size, owner, error
func decodeRequest(in []byte) (*string, *string, *string, *int, *[]byte, error) {
	theType, subject, action, resource, owner, status, message, size, buf, err:= decodeMessage(int)
	if(theType!=REQUEST)
		return nil,nil,nil,nil,nil, errors.New("Cant decode request")
	return subject, action, resource, size, owner, nil
}

// return: status, message, size, error
func getResponse(conn net.Conn) (string*, string*, int*, error) {
	util.NewMessageStream(conn)
	var buf []byte
	ms.ReadMessage(buf)
	theType, subject, action, resource, status, message, size, buf, err:= decodeMessage(buf)
	if(theType!=RESPONSE) {
		return nil, nil, nil, errors.New("Malformed message")
	}
	return &status, &message, &size, nil
}

func sendResponse(conn net.Conn, status string, message string, size int) error {
	ms, err:= util.NewMessageStream(conn)
	if(err!=nil) {
		return err
	}
	protoMessage:= encodeMessage(RESPONSE, nil,  nil, nil, status, message,  size,  nil )
	out, err: proto.Marshal(protoMessage)
	ms.WriteMessage(out)
	if(err!=nil) {
		return err
	}
	return nil
}

func getFile(conn net.Conn, filename string, size, int, key []byte) {
	// open the file
	// for each block {
	// 	read block from file
	//	decrypt block
	//	if last-block
	// 		encode block in message, file-end message
	//	else
	//		encode block in message, next_block
	// 	send block
	// }
}

func sendFile(conn net.Conn, filename string, size int, key []byte) {
	// creat the file
	// for each block {
	//	read block
	// 	decode message block
	//	encrypt block
	// 	send block
	// 	if last block
	//		break
	// }
}

func readRequest(conn net.Conn, resourcename string) error {
	// is it here?
	// get size and file name
	status:= "succeeded"
	sendResponse(conn, status, nil, size)
	sendFile(conn, filename, size, SymKeys)
	return nil
}

func writeRequest(conn net.Conn, resourcename string) error {
	// is it here?
	// get size and file name
	status:= "succeeded"
	sendResponse(conn, status, nil, size)
	getFile(conn, filename, size, SymKeys)
	return nil
}

func createRequest(conn net.Conn, subject string, resourcename string, owner []byte) error {
	// is it here?
	status:= "succeeded"
	sendResponse(conn, status, nil, size)
	getFile(conn, filename, size, SymKeys)
	return nil
}

func deleteRequest(conn net.Conn, resourcename string) error {
	return errors.New("deleteRequest not implemented")
}

func addRuleRequest(conn net.Conn, resourcename string) error {
	return errors.New("addRuleRequest not implemented")
}

func addOwnerRequest(conn net.Conn, resourcename string) error {
	return errors.New("addOwnerRequest not implemented")
}

func deleteOwnerRequest(conn net.Conn, resourcename string) error {
	return errors.New("deleteOwnerRequest not implemented")
}

// first return value is terminate flag
func (m *ResourceMaster) HandleServiceRequest(conn net.Conn, request []byte) (bool, error) {
	// decode request
	fpMessage, err:= proto.Unmarshal(request)
	subject, action, resourcename, owner, err:= decodeRequest(fpMessage)

	// is it authorized?
	ok:= m.guard.IsAuthorized(subject, action, resourcename)
	if ok == nil {
		status= "failed"
		message= "unauthorized"
		sendErrorResponse(status, message);
		return  false, errors.New("unauthorized")
	}

	var status string
	var message string
	if(action=="create") {
		err:= createRequest(conn, subject, resourcename, owner)
		return false, err
	} else if(action=="delete") {
		err:= deleteRequest(conn, subject, resourcename)
		return false, err
	} else if(action=="read") {
		err:= readRequest(conn, subject, resourcename)
		return false, err
	} else if(action=="write") {
		err:= writeRequest(conn, subject, resourcename)
		return false, err
	} else if(action=="terminate") {
		return  true, nil
	} else {
		status= "failed"
		message= "unsupported action"
		sendErrorResponse(status, message);
		return  false, errors.New("unsupported action")
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
