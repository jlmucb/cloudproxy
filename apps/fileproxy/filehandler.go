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
// File: fileproxy.go

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
	resourceSize		string
	dateCreated		string
	dateModified		string
	resourcePointer		string
	authenticatorType	string
	authenticator		[][]byte
}


type ResourceMaster {
	program		auth.Prin
	guard		tao.Guard
	baseDirectory	string
	resourceArray	[]ResourceInfo
	// Rules
};

// master structure
var fileproxy ResourceMaster


func (r ResourceMaster*)  MarshalResourceMaster() (string, err) {
}

func UnmarshalMarshalResourceMaster(in string) (*ResourceMaster, err) {
}

func (r ResourceInfo*)  MarshalResourceInfo() (string, err) {
}

func UnmarshalMarshalResourceInfo(in string) (*ResourceInfo, err) {
}

func GetResourceData() error {
}

func SaveResourceData() error {
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
func InitGuard(g *tao.Guard) {
}

func InitResources(handlerFile string, masterInfoFile string,  resourceInfoArrayFile string) error {
}

func (h *ResourceMaster) HandleServiceRequest(request string) error {
}
