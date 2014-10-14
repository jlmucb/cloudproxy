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
	"errors"
	//"flag"
	//"os"
	"fmt"
	"net"
	"code.google.com/p/goprotobuf/proto"
	 tao "github.com/jlmucb/cloudproxy/tao"
	 // "github.com/jlmucb/cloudproxy/tao/auth"
	 // taonet "github.com/jlmucb/cloudproxy/tao/net"
	"github.com/jlmucb/cloudproxy/util"
)

// Resource types: files, channels

type ResourceInfo struct {
	resourceName		string
	resourceType		string
	resourceStatus		string
	resourceLocation	string
	resourceSize		int
	resourceOwner		[]byte   // x509 cert
	dateCreated		string
	dateModified		string
	authenticatorType	string	 // sha hash usually
	authenticator		[][]byte
}


type ResourceMaster struct {
	program		string
	Guard		*tao.Guard
	baseDirectory	string
	resourceArray	[100]ResourceInfo
	// Rules
};

func (m *ResourceMaster) Find(resourcename string) (*ResourceInfo, error) {
	for i:=0; i< len(m.resourceArray);i++ {
		 if(m.resourceArray[i].resourceName==resourcename) {
			 return &m.resourceArray[i], nil
		 }
	}
	return nil, nil
}

func (m *ResourceMaster) Insert(path, string, resourcename string, owner []byte) (*ResourceInfo, error) {
	found, err:=  m.Find(resourcename)
	if(err!=nil) {
		return nil, err
	}
	if(found!=nil) {
		return found, nil
	}
	n:=  len(m.resourceArray)
	if((n+1)>cap(m.resourceArray)) {
		fmt.Printf("Todo: increase resourceArray size\n")
		return nil,  errors.New("resourceArray too small")
	}
	// m.resourceArray= m.resourceArray[0:n+1]
	// m.resourceArray= m.resourceArray[0:n+1]
	resInfo:=   new(ResourceInfo)
	m.resourceArray[n]=  *resInfo
	m.resourceArray[n].resourceName= resourcename
	m.resourceArray[n].resourceType= "file"
	m.resourceArray[n].resourceStatus= "created"
	m.resourceArray[n].resourceLocation=  path+resourcename
	m.resourceArray[n].resourceOwner=  owner
	return resInfo, nil
}

// return: type, subject, action, resource, owner, status, message, size_buf, buf, error
func decodeMessage(in []byte) (*int, *string,  *string, *string, *[]byte,
		      *string, *string,  *int,  *[]byte, error) {
fmt.Printf("decodeMessage\n")
	fpMessage:= new(FPMessage)
	err:= proto.Unmarshal(in, fpMessage)
	if(err!=nil) {
		return nil, nil,nil,nil,nil,nil,nil,nil,nil, err
	}
	theType:= int(*fpMessage.MessageType)
	if(theType==int(MessageType_REQUEST)) {
		subject:= *fpMessage.SubjectName
		action:= *fpMessage.ActionName
		resourcename:= *fpMessage.ResourceName
		// TODO: check to see if its nil
		owner:=  fpMessage.ResourceOwner
		return &theType, &subject, &action, &resourcename, &owner, nil,nil,nil,nil,nil
	} else if (theType==int(MessageType_RESPONSE)) {
		status:= *fpMessage.StatusOfRequest
		message:= *fpMessage.MessageFromRequest
		return &theType, nil,nil,nil, nil, &status, &message, nil,nil,nil
	} else if (theType==int(MessageType_FILE_NEXT) || theType==int(MessageType_FILE_LAST)) {
		size:= int(*fpMessage.BufferSize)
		out:= fpMessage.TheBuffer
		return &theType, nil, nil,nil,nil, nil,nil, &size, &out, nil
	}

	return nil, nil,nil,nil,nil,nil,nil,nil,nil, errors.New("unknown message type")
}

func encodeMessage(theType int, subject *string,  action *string, resourcename *string, owner *[]byte,
		   status *string, message *string,  size *int,  buf []byte) ([]byte, error) {
fmt.Printf("encodeMessage\n")
	protoMessage:=  new(FPMessage)
	protoMessage.MessageType= proto.Int(theType)
	if(theType==int(MessageType_REQUEST)) {
		protoMessage.SubjectName= proto.String(*subject)
		protoMessage.ActionName= proto.String(*action)
		protoMessage.ResourceName= proto.String(*resourcename)
		// TODO: protoMessage.ResourceOwner= proto.Bytes(*owner)
	} else if (theType==int(MessageType_RESPONSE)) {
		protoMessage.StatusOfRequest= proto.String(*status)
		protoMessage.MessageFromRequest= proto.String(*message)
	} else if ( theType==int(MessageType_FILE_NEXT) || theType==int(MessageType_FILE_LAST)) {
		protoMessage.BufferSize= proto.Int(*size)
		//Fix: protoMessage.TheBuffer= proto.Bytes(buf)
	} else {
		return nil, errors.New("unknown message type\n")
	}
	out, err:=proto.Marshal(protoMessage)
	return out, err
}

func (m *ResourceMaster) Delete(resourceName string) error {
	return nil // not implemented
}

func (m *ResourceMaster) encodeMaster() ([]byte, error){
fmt.Printf("encodeMaster\n")
	protoMessage:=  new(FPResourceMaster)
	protoMessage.PrinName= proto.String(m.program);
	protoMessage.BaseDirectoryName= proto.String(m.baseDirectory);
	protoMessage.NumFileinfos= proto.Int(len(m.resourceArray))
	out, err:= proto.Marshal(protoMessage)
	return out, err
}

func (m *ResourceMaster) decodeMaster(in []byte) (*int, error) {
fmt.Printf("decodeMaster\n")
	rMessage:= new(FPResourceMaster)
	_= proto.Unmarshal(in, rMessage)
	m.program= *rMessage.PrinName
	m.baseDirectory= *rMessage.BaseDirectoryName
	size:=  *rMessage.NumFileinfos
	isize:= int(size)  //TODO: Fix
	return &isize, nil
}

func (r *ResourceInfo) encodeResourceInfo() ([]byte, error){
fmt.Printf("encodeResourceInfo\n")
	protoMessage:=  new(FPResourceInfo)
	protoMessage.ResourceName= proto.String(r.resourceName);
	protoMessage.ResourceType= proto.String(r.resourceType);
	protoMessage.ResourceStatus= proto.String(r.resourceStatus);
	protoMessage.ResourceLocation= proto.String(r.resourceLocation);
	protoMessage.ResourceSize= proto.Int(r.resourceSize);
	//Fix: protoMessage.ResourceOwner= proto.Bytes(r.resourceOwner);
	out, err:= proto.Marshal(protoMessage)
	return out,err 
}

func (r *ResourceInfo) decodeResourceInfo(in []byte) error {
fmt.Printf("decodeResourceInfo\n")
	rMessage:= new(FPResourceInfo)
	_= proto.Unmarshal(in, rMessage)
	r.resourceName= *rMessage.ResourceName
	r.resourceType= *rMessage.ResourceType
	r.resourceLocation= *rMessage.ResourceLocation
	r.resourceSize= int(*rMessage.ResourceSize)
	r.resourceOwner= rMessage.ResourceOwner
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

func (m *ResourceMaster) PrintMaster(printResources bool) {
	fmt.Printf("Program principal: %s\n", m.program)
	fmt.Printf("Base Directory: %s\n", m.baseDirectory)
	fmt.Printf("%d resources\n", len(m.resourceArray))
	if(printResources) {
		for i:=0; i< len(m.resourceArray);i++ {
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
fmt.Printf("InitGuard\n")
	//fileGuard := tao.NewTemporaryDatalogGuard()
	// for now, liberal guard
	*m.Guard=  tao.LiberalGuard
	// no need for rules
	return nil
}

func (m *ResourceMaster) SaveRules(g *tao.Guard, rulefile string) error {
fmt.Printf("SaveRules\n")
	// no need for rules
	return nil
}

func (m *ResourceMaster) GetResourceData(masterInfoFile string,  resourceInfoArrayFile string) error {
fmt.Printf("GetResourceData\n")
	// read master info
	// decrypt it
	// read resourceinfos
	// decrypt it

	// read rule file
	// decrypt it
	return nil
}

func (m *ResourceMaster) SaveResourceData(masterInfoFile string,  resourceInfoArrayFile string) error {
fmt.Printf("SaveResourceData\n")
	// encrypt master info
	// write master info
	// encrypt fileinfos
	// write fileinfos
	// encrypt rules
	// write rules
	return nil
}

// return values: subject, action, resourcename, size, error
func encodeRequest(subject string, action string, resourcename string, owner []byte) ([]byte, error) {
fmt.Printf("encodeRequest\n")
	out,err:= encodeMessage(int(MessageType_REQUEST), &subject,  &action, &resourcename, &owner,
	                   nil, nil,  nil,  nil)
	return  out, err
}

// return values: subject, action, resourcename, owner, error
func decodeRequest(in []byte) (*string, *string, *string, *[]byte, error) {
fmt.Printf("decodeRequest\n")
	theType, subject, action, resource, owner, status, message, size, buf, err:= decodeMessage(in)
	if(*theType!=int(MessageType_REQUEST)) {
		return nil,nil,nil,nil, errors.New("Cant decode request")
	}
	if (err!=nil) {
		return  nil, nil, nil, nil, err
	}
	if(status!=nil || message!=nil || size!=nil  || buf!=nil) {
		return  nil, nil, nil, nil, errors.New("malformed request")
	}
	return subject, action, resource, owner, nil
}

// return: status, message, size, error
func getResponse(conn net.Conn) (*string, *string, *int, error) {
fmt.Printf("getResponse\n")
	ms:= util.NewMessageStream(conn)
	strbytes,err:= ms.ReadString()
	if(err!=nil) {
		return nil, nil, nil, err
	}
	theType, subject, action, resource, owner, status, message, size, out, err:= decodeMessage([]byte(strbytes))
	if (err!=nil) {
		return  nil, nil, nil, err
	}
	if(subject!=nil || action!=nil || resource!=nil || owner!=nil || size!=nil  || out!=nil) {
		return  nil, nil, nil, errors.New("malformed request")
	}
	if(*theType!=int(MessageType_RESPONSE)) {
		return nil, nil, nil, errors.New("Wrong message type")
	}
	return status, message, size, nil
}

func sendResponse(conn net.Conn, status string, message string, size int) error {
fmt.Printf("sendResponse\n")
	ms:= util.NewMessageStream(conn)
	out,_:= encodeMessage(int(MessageType_RESPONSE), nil, nil,  nil, nil, &status, &message,  &size,  nil)
	ms.WriteString(string(out))
	return nil
}

func getFile(conn net.Conn, filename string, size, int, key []byte) {
fmt.Printf("getFile\n")
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
fmt.Printf("sendFile\n")
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
fmt.Printf("readRequest\n")
	// is it here?
	// get size and file name
	status:= "succeeded"
	size:= 10  // what size?
	sendResponse(conn, status, "", size)
	//TODO: sendFile(conn, resourcename, size, SymKeys)
	return nil
}

func writeRequest(conn net.Conn, resourcename string) error {
fmt.Printf("writeRequest\n")
	// is it here?
	// get size and file name
	status:= "succeeded"
	size:= 10 // TODO: fix
	sendResponse(conn, status, "", size)
	// TODO: getFile(conn, resourcename, size, SymKeys)
	return nil
}

func createRequest(conn net.Conn, resourcename string, owner []byte) error {
fmt.Printf("createRequest\n")
	// is it here?
	status:= "succeeded"
	size:= 10 //TODO: what size
	sendResponse(conn, status, "", size)
	// TODO: getFile(conn, resourcename, size, SymKeys)
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
fmt.Printf("HandleServiceRequest\n")
	_, action, resourcename, owner, err:= decodeRequest(request)
	if(err!=nil) {
		return false, err
	}

	// is it authorized?
	ok:= true; // TODO: m.guard.IsAuthorized(subject, action, resourcename) 
	if ok == false {
		status:= "failed"
		message:= "unauthorized"
		size:= 10  // TODO: fix
		sendResponse(conn, status, message, size);
		return  false, errors.New("unauthorized")
	}

	if(*action=="create") {
		err:= createRequest(conn, *resourcename, *owner)
		return false, err
	} else if(*action=="delete") {
		err:= deleteRequest(conn, *resourcename)
		return false, err
	} else if(*action=="read") {
		err:= readRequest(conn, *resourcename)
		return false, err
	} else if(*action=="write") {
		err:= writeRequest(conn, *resourcename)
		return false, err
	} else if(*action=="terminate") {
		return  true, nil
	} else {
		status:= "failed"
		message:= "unsupported action"
		sendResponse(conn, status, message, 0);
		return  false, errors.New("unsupported action")
	}
}

func (m *ResourceMaster) InitMaster(masterInfoDir string, prin string)  error {
fmt.Printf("InitMaster\n")
	m.GetResourceData(masterInfoDir+"masterinfo",  masterInfoDir+"resources")
	m.InitGuard(m.Guard, masterInfoDir+"rules")
	return nil
}

func (m *ResourceMaster) SaveMaster(masterInfoDir string)  error {
fmt.Printf("SaveMaster\n")
	err:= m.SaveResourceData(masterInfoDir+"masterinfo",  masterInfoDir+"resources")
	if err!=nil {
		fmt.Printf("cant m.SaveResourceData\n")
		return err
	}
	return m.SaveRules(m.Guard, masterInfoDir+"rules")
}
