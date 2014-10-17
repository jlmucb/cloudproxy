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
	"errors"
	"fmt"
	"code.google.com/p/goprotobuf/proto"
	 tao "github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/util"
	//"flag"
	//"os"
	// "github.com/jlmucb/cloudproxy/tao/auth"
	// taonet "github.com/jlmucb/cloudproxy/tao/net"
)

// Resource types: files, channels

type ResourceInfo struct {
	resourceName		string
	resourceType		string
	resourceStatus		string
	resourceLocation	string
	resourceSize		int
	resourceOwner		string // x509 cert
	dateCreated		string
	dateModified		string
	authenticatorType	string	 // sha hash usually
	authenticator		[][]byte
}


type ResourceMaster struct {
	program		string
	Guard		tao.Guard
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

func (m *ResourceMaster) Insert(path string, resourcename string, owner string) (*ResourceInfo, error) {
	found, err:=  m.Find(resourcename)
	if(err!=nil) {
		return nil, err
	}
	if(found!=nil) {
		return found, nil
	}
	n:=  len(m.resourceArray)
	if((n+1)>cap(m.resourceArray)) {
		fmt.Printf("filehandler: increase resourceArray size\n")
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
func DecodeMessage(in []byte) (*int, *string,  *string, *string, *string,
		      *string, *string,  *int,  *[]byte, error) {
			      fmt.Printf("filehandler: DecodeMessage\n")
	var the_type32 *int32
	var the_type int
	var subject *string
	var action *string
	var resource *string
	var owner *string
	var status *string
	var message *string
	var size_buf *int
	var buf *[]byte

	the_type= -1
	the_type32= nil
	subject= nil
	action= nil
	resource= nil
	owner= nil
	status= nil
	message= nil
	size_buf= nil
	buf= nil

	fpMessage:= new(FPMessage)
	err:= proto.Unmarshal(in, fpMessage)
	the_type32= fpMessage.MessageType
	if(the_type32==nil) {
		return &the_type, subject, action, resource, owner, status, message, size_buf, buf,
		       errors.New("No type")
	}
	the_type= int(*the_type32)
	if(the_type==int(MessageType_REQUEST)) {
		subject= fpMessage.SubjectName
		action= fpMessage.ActionName
		resource= fpMessage.ResourceName
		owner=  fpMessage.ResourceOwner
		return &the_type, subject, action, resource, owner, status, message, size_buf, buf, err
	} else if (the_type==int(MessageType_RESPONSE)) {
		if(fpMessage.StatusOfRequest!=nil) {
			status= fpMessage.StatusOfRequest
		}
		if(fpMessage.MessageFromRequest!=nil) {
			message= fpMessage.MessageFromRequest
		}
		return &the_type, subject, action, resource, owner, status, message, size_buf, buf, err
	} else if (the_type==int(MessageType_FILE_NEXT) || the_type==int(MessageType_FILE_LAST)) {
		size32:= *fpMessage.BufferSize
		size1:= int(size32)
		buffer:= fpMessage.TheBuffer
		buf:= &buffer
		return &the_type, subject, action, resource, owner, status, message, &size1, buf,
			errors.New("No type")
	}
	fmt.Printf("Decode message bad message type %d\n", the_type)
	return &the_type, subject, action, resource, owner, status, message, size_buf, buf,
		errors.New("Unknown message type")
}

func EncodeMessage(theType int, subject *string,  action *string, resourcename *string, owner *string,
		   status *string, reqMessage *string, size *int,  buf []byte) ([]byte, error) {
			   fmt.Printf("filehandler: encodeMessage\n")
	fmt.Printf("EncodeMessage %d\n", theType)
	protoMessage:=  new(FPMessage)
	protoMessage.MessageType= proto.Int(theType)
	if(theType==int(MessageType_REQUEST)) {
		protoMessage.SubjectName= proto.String(*subject)
		protoMessage.ActionName= proto.String(*action)
		protoMessage.ResourceName= proto.String(*resourcename)
		protoMessage.ResourceOwner= proto.String(*owner)
	} else if (theType==int(MessageType_RESPONSE)) {
		protoMessage.StatusOfRequest= proto.String(*status)
		protoMessage.MessageFromRequest= proto.String(*reqMessage)
	} else if ( theType==int(MessageType_FILE_NEXT) || theType==int(MessageType_FILE_LAST)) {
		protoMessage.BufferSize= proto.Int(*size)
		//Fix: protoMessage.TheBuffer= proto.Bytes(buf)
	} else {
		fmt.Print("EncodeMessage, Bad message type: %d\n", theType);
		return nil, errors.New("encodemessage, unknown message type\n")
	}
	out, err:=proto.Marshal(protoMessage)
	fmt.Printf("Marshaled %d\n", len(out))
	return out, err
}

func (m *ResourceMaster) Delete(resourceName string) error {
	return nil // not implemented
}

func (m *ResourceMaster) EncodeMaster() ([]byte, error){
	fmt.Printf("filehandler: encodeMaster\n")
	protoMessage:=  new(FPResourceMaster)
	protoMessage.PrinName= proto.String(m.program);
	protoMessage.BaseDirectoryName= proto.String(m.baseDirectory);
	protoMessage.NumFileinfos= proto.Int(len(m.resourceArray))
	out, err:= proto.Marshal(protoMessage)
	return out, err
}

func (m *ResourceMaster) DecodeMaster(in []byte) (*int, error) {
	fmt.Printf("filehandler: DecodeMaster\n")
	rMessage:= new(FPResourceMaster)
	_= proto.Unmarshal(in, rMessage)
	m.program= *rMessage.PrinName
	m.baseDirectory= *rMessage.BaseDirectoryName
	size:=  *rMessage.NumFileinfos
	isize:= int(size)  //TODO: Fix
	return &isize, nil
}

func (r *ResourceInfo) EncodeResourceInfo() ([]byte, error){
	fmt.Printf("filehandler: encodeResourceInfo\n")
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

func (r *ResourceInfo) DecodeResourceInfo(in []byte) error {
	fmt.Printf("filehandler: DecodeResourceInfo\n")
	rMessage:= new(FPResourceInfo)
	_= proto.Unmarshal(in, rMessage)
	r.resourceName= *rMessage.ResourceName
	r.resourceType= *rMessage.ResourceType
	r.resourceLocation= *rMessage.ResourceLocation
	r.resourceSize= int(*rMessage.ResourceSize)
	r.resourceOwner= *rMessage.ResourceOwner
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

func (m *ResourceMaster) InitGuard(rulefile string) error {
	fmt.Printf("filehandler: InitGuard\n")
	//fileGuard := tao.NewTemporaryDatalogGuard()
	// for now, liberal guard
	g:= tao.LiberalGuard
	m.Guard=  g
	// no need for rules
	return nil
}

func (m *ResourceMaster) SaveRules(g tao.Guard, rulefile string) error {
	fmt.Printf("filehandler: SaveRules\n")
	// no need for rules
	return nil
}

func (m *ResourceMaster) GetResourceData(masterInfoFile string,  resourceInfoArrayFile string) error {
	fmt.Printf("filehandler: GetResourceData\n")
	// read master info
	// decrypt it
	// read resourceinfos
	// decrypt it

	// read rule file
	// decrypt it
	return nil
}

func (m *ResourceMaster) SaveResourceData(masterInfoFile string,  resourceInfoArrayFile string) error {
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
	out,err:= EncodeMessage(int(MessageType_REQUEST), &subject,  &action, &resourcename, &owner,
	                   nil, nil,  nil,  nil)
	return  out, err
}

// return values: subject, action, resourcename, owner, error
func DecodeRequest(in []byte) (*string, *string, *string, *string, error) {
	fmt.Printf("filehandler: DecodeRequest\n")
	theType, subject, action, resource, owner, status, message, size, buf, err:= DecodeMessage(in)
	if(err!=nil) {
		fmt.Printf("DecodeRequest error: ", err)
		fmt.Printf("\n")
		return  nil, nil, nil, nil, err
	}
	PrintRequest(subject,  action, resource, owner)
	if(*theType!=int(MessageType_REQUEST)) {
		return nil,nil,nil,nil, errors.New("Cant Decode request")
	}
	if (err!=nil) {
		return  nil, nil, nil, nil, err
	}
	if(status!=nil || message!=nil || size!=nil  || buf!=nil) {
		return  nil, nil, nil, nil, errors.New("malformed request")
	}
	return subject, action, resource, owner, nil
}

func PrintRequest(subject *string,  action *string, resource *string, owner* string) {
	fmt.Printf("PrintRequest\n")
	if(subject!=nil) {
		fmt.Printf("\tsubject: %s\n", *subject)
	}
	if(action!=nil) {
		fmt.Printf("\taction: %s\n", *action)
	}
	if(resource!=nil) {
		fmt.Printf("\tresource: %s\n", *resource)
	}
	if(owner!=nil) {
		fmt.Printf("\towner: %s\n", *owner)
	}
}

// return: status, message, size, error
func GetResponse(ms *util.MessageStream) (*string, *string, *int, error) {
	fmt.Printf("filehandler: GetResponse\n")
	strbytes,err:= ms.ReadString()
	if(err!=nil) {
		return nil, nil, nil, err
	}
	fmt.Printf("GetResponse read %d bytes\n", len(strbytes))
	theType, _, _, _, _, status, message, size, _, err:= DecodeMessage([]byte(strbytes))
	if (err!=nil) {
		fmt.Printf("DecodeMessage error in GetResponse\n")
		return  nil, nil, nil, err
	}
	if(status==nil) {
		fmt.Printf("DecodeMessage in getresponse returned nil status")
	} else{
		fmt.Printf("DecodeMessage in getresponse returned %s (status)\n", *status)
	}
	fmt.Printf("GetResponse \n", len(strbytes))
	if(*theType!=int(MessageType_RESPONSE)) {
		return nil, nil, nil, errors.New("Wrong message type")
	}
	return status, message, size, nil
}

func PrintResponse (status *string, message *string, size *int) {
	fmt.Printf("PrintResponse\n")
	if(status!=nil) {
		fmt.Printf("\tstatus: %s\n", *status)
	} else {
		fmt.Printf("\tstatus: empty\n")
	}
	if(message!=nil) {
		fmt.Printf("\tmessage: %s\n", *message)
	}
	if(size!=nil) {
		fmt.Printf("\tsize: %d\n", *size)
	}
}

func SendResponse(ms *util.MessageStream, status string, message string, size int) error {
	out,err:= EncodeMessage(int(MessageType_RESPONSE), nil, nil, nil, nil, &status, &message,  &size,  nil)
	if (err!=nil) {
		fmt.Printf("EncodeMessage fails in SendResponse\n")
		return err
	}
	send:= string(out)
	fmt.Printf("filehandler: SendResponse sending %s %s %d\n", status, message, len(send))
	n, err:= ms.WriteString(send)
	if(err!=nil) {
		fmt.Printf("filehandler: SendResponse Writestring error %d\n", n, err)
		return err
	}
	return nil
}

func readRequest(m *ResourceMaster, ms *util.MessageStream, resourcename string) error {
	fmt.Printf("filehandler: readRequest\n")
	// is it here?
	// get size and file name
	status:= "succeeded"
	SendResponse(ms, status, "", 0)
	//TODO: SendFile(ms, resourcename, size, SymKeys)
	return nil
}

func writeRequest(m *ResourceMaster, ms *util.MessageStream, resourcename string) error {
	fmt.Printf("filehandler: writeRequest\n")
	// is it here?
	// get size and file name
	status:= "succeeded"
	SendResponse(ms, status, "", 0)
	// TODO: GetFile(ms, resourcename, size, SymKeys)
	return nil
}

func createRequest(m *ResourceMaster, ms *util.MessageStream,
		   resourcename string, owner string) error {
	fmt.Printf("filehandler: createRequest\n")
	rInfo, _:= m.Find(resourcename)
	if(rInfo!=nil) {
		SendResponse(ms, "failed", "resource exists", 0)
		return nil
	}
	rInfo, _= m.Insert(m.baseDirectory, resourcename, owner)
	if(rInfo!=nil) {
		SendResponse(ms, "failed", "cant insert resource", 0)
		return nil
	}
	status:= "succeeded"
	SendResponse(ms, status, "", 0)
	// TODO: GetFile(ms, resourcename, size, SymKeys)
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
	subject, action, resourcename, owner, err:= DecodeRequest(request)
	if(err!=nil) {
		return false, err
	}
	fmt.Printf("HandleServiceRequest\n")
	PrintRequest(subject, action, resourcename, owner)

	// is it authorized?
	ok:= true; // TODO: m.guard.IsAuthorized(subject, action, resourcename) 
	if ok == false {
		status:= "failed"
		message:= "unauthorized"
		size:= 10  // TODO: fix
		SendResponse(ms, status, message, size);
		return  false, errors.New("unauthorized")
	}

	if(*action=="create") {
		if(resourcename==nil || owner==nil) {
			return false, errors.New("Nil parameters for createRequest")
		}
		err:= createRequest(m, ms, *resourcename, *owner)
		return false, err
	} else if(*action=="delete") {
		err:= deleteRequest(m, ms, *resourcename)
		return false, err
	} else if(*action=="read") {
		err:= readRequest(m, ms, *resourcename)
		return false, err
	} else if(*action=="write") {
		err:= writeRequest(m, ms, *resourcename)
		return false, err
	} else if(*action=="terminate") {
		return  true, nil
	} else {
		status:= "failed"
		message:= "unsupported action"
		SendResponse(ms, status, message, 0);
		return  false, errors.New("unsupported action")
	}
}

func (m *ResourceMaster) InitMaster(masterInfoDir string, prin string)  error {
	fmt.Printf("filehandler: InitMaster\n")
	m.GetResourceData(masterInfoDir+"masterinfo",  masterInfoDir+"resources")
	m.InitGuard(masterInfoDir+"rules")
	return nil
}

func (m *ResourceMaster) SaveMaster(masterInfoDir string)  error {
	fmt.Printf("filehandler: SaveMaster\n")
	err:= m.SaveResourceData(masterInfoDir+"masterinfo",  masterInfoDir+"resources")
	if err!=nil {
		fmt.Printf("filehandler: cant m.SaveResourceData\n")
		return err
	}
	return m.SaveRules(m.Guard, masterInfoDir+"rules")
}
