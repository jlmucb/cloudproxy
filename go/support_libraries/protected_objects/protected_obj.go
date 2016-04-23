// Copyright (c) 2014, Google Inc. All rights reserved.
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

// Package protected_objects stores, searches and chains protected objects like keys
// and files.

package protected_objects 

import (
	"container/list"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tpm2"
)

func PrintObject(obj *ObjectMessage) {
	fmt.Printf("Object %s, epoch %d\n", *obj.ObjId.ObjName, *obj.ObjId.ObjEpoch)
	fmt.Printf("\ttype %s, status %s, notbefore: %s, notafter: %s\n", *obj.ObjType,
		*obj.ObjStatus, *obj.NotBefore, *obj.NotAfter)
	fmt.Printf("Object value: %x\n", obj.ObjVal)
}

func PrintProtectedObject(obj *ProtectedObjectMessage) {
	fmt.Printf("Object %s, epoch %d\n", *obj.ProtectedObjId.ObjName, *obj.ProtectedObjId.ObjEpoch)
	fmt.Printf("Object %s, epoch %d\n", *obj.ProtectorObjId.ObjName, *obj.ProtectorObjId.ObjEpoch)
}

func PrintNode(obj *NodeMessage) {
	fmt.Printf("ProtectedObject %s, epoch %d\n", *obj.ProtectedObjId.ObjName,
		 *obj.ProtectedObjId.ObjEpoch)
	fmt.Printf("ProtectorObject %s, epoch %d\n", *obj.ProtectorObjId.ObjName,
		 *obj.ProtectorObjId.ObjEpoch)
}

// Generic string matcher
//	if names list is nil, anything matches
//	otherwise name must match one string in names list
func stringMatch(name *string, names []string) bool {
	if names == nil {
		return true
	}
	if name == nil {
		return false
	}
	for _, v := range(names) {
		if v == *name {
			return true
		}
	}
	return false
}

// Create the object with the provided data.
func CreateObject(name string, epoch int32, obj_type *string, status *string, notBefore *time.Time,
		notAfter *time.Time, v []byte) (*ObjectMessage, error) {
	obj_id := &ObjectIdMessage {
		ObjName: &name,
		ObjEpoch: &epoch,
	}
	str_notBefore := notBefore.String()
	str_notAfter := notAfter.String()
	obj := &ObjectMessage {
		ObjId: obj_id,
		ObjType: obj_type,
		ObjStatus: status,
		NotBefore: &str_notBefore,
		NotAfter: &str_notAfter,
		ObjVal: v,
	}
	return obj, nil
}

// Add the indicated objectid to the list.
func AddObjectId(l *list.List, obj ObjectIdMessage) error {
	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(ObjectIdMessage)
		if o.ObjName == obj.ObjName && o.ObjEpoch == obj.ObjEpoch {
			return nil
		}
	}
	l.PushFront(interface{}(obj))
	return nil
}

// Add the indicated protected object to the list.
func AddObject(l *list.List, obj ObjectMessage) error {
	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(ObjectMessage)
		if o.ObjId.ObjName == obj.ObjId.ObjName && o.ObjId.ObjEpoch == obj.ObjId.ObjEpoch {
			return nil
		}
	}
	l.PushFront(interface{}(obj))
	return nil
}

// Add the indicated protected object to the list.
func AddProtectedObject(l *list.List, obj ProtectedObjectMessage) error {
	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(ProtectedObjectMessage)
		if o.ProtectedObjId.ObjName == obj.ProtectedObjId.ObjName &&
		   o.ProtectedObjId.ObjEpoch == obj.ProtectedObjId.ObjEpoch &&
		   o.ProtectorObjId.ObjName == obj.ProtectorObjId.ObjName &&
		   o.ProtectorObjId.ObjEpoch == obj.ProtectorObjId.ObjEpoch {
			return nil
		}
	}
	l.PushFront(interface{}(obj))
	return nil
}

// Add the indicated node to the list.
func AddNode(l *list.List, obj NodeMessage) error {
	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(NodeMessage)
		if o.ProtectedObjId.ObjName == obj.ProtectedObjId.ObjName &&
		   o.ProtectedObjId.ObjEpoch == obj.ProtectedObjId.ObjEpoch &&
		   o.ProtectorObjId.ObjName == obj.ProtectorObjId.ObjName &&
		   o.ProtectorObjId.ObjEpoch == obj.ProtectorObjId.ObjEpoch {
			return nil
		}
	}
	l.PushFront(interface{}(obj))
	return nil
}

// Remove the referenced object from the list.
func DeleteObject(l *list.List, name string, epoch int32) error {
	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(ObjectMessage)
		if *o.ObjId.ObjName == name && *o.ObjId.ObjEpoch == epoch {
			l.Remove(e)
			break;
		}
	}
	return nil
}

// Remove the referenced protected object from the list.
func DeleteProtectedObject(l *list.List, name string, epoch int32) error {
	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(ProtectedObjectMessage)
		if *o.ProtectedObjId.ObjName == name && *o.ProtectedObjId.ObjEpoch == epoch {
			l.Remove(e)
			break;
		}
	}
	return nil
}

// Remove the referenced node from the list.
func DeleteNode(l *list.List, protectorName string, protectorEpoch int32,
	protectedName string, protectedEpoch int32) error {
	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(ProtectedObjectMessage)
		if *o.ProtectedObjId.ObjName == protectedName &&
				*o.ProtectedObjId.ObjEpoch == protectedEpoch  &&
				*o.ProtectorObjId.ObjName == protectorName &&
				*o.ProtectorObjId.ObjEpoch == protectorEpoch {
			l.Remove(e)
			break;
		}
	}
	return nil
}

// Find objects protected by object with given name and epoch.
func FindProtectedNodes(l *list.List, name string, epoch int32) (*list.List) {
	r := list.New()

	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(NodeMessage)
		if epoch != 0 && epoch != *o.ProtectedObjId.ObjEpoch {
			continue
		}
		if name == *o.ProtectedObjId.ObjName {
			r.PushFront(o)
		}
        }
	return r
}

// Find protectors of the object with given name and epoch.
func FindProtectorNodes(l *list.List, name string, epoch int32) (*list.List) {
	r := list.New()

	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(NodeMessage)
		if epoch != 0 && epoch != *o.ProtectorObjId.ObjEpoch {
			continue
		}
		if name == *o.ProtectorObjId.ObjName {
			r.PushFront(o)
		}
        }
	return r
}

// Find object with given name, epoch, with one of the offered types and names.
// A nil types or names list matches anything (even nil)
func FindObject(l *list.List, name string, epoch int32, types []string, statuses []string) (*ObjectMessage) {
	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(ObjectMessage)
		if !stringMatch(o.ObjStatus, statuses) || !stringMatch(o.ObjType, statuses) {
			continue
		}
		if epoch != 0 && epoch != *o.ObjId.ObjEpoch {
			continue
		}
		if name == *o.ObjId.ObjName {
			return &o
		}
        }
	return nil
}

// Get object with given name and latest epoch.
func GetLatestEpoch(l *list.List, name string, status []string) (*ObjectMessage) {
	latest := 0
	var result *ObjectMessage
	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(ObjectMessage)
		PrintObject(&o)
		if *o.ObjId.ObjName != name {
			continue
		}
		if o.ObjId.ObjEpoch == nil {
			continue
		}
		if result == nil {
			result = &o
			latest = int(*o.ObjId.ObjEpoch)
			continue
		}
		if int(*o.ObjId.ObjEpoch) > latest {
			latest = int(*o.ObjId.ObjEpoch)
			result = &o
		}
	}
	return result 
}

// Get object with given name and earliest epoch.
func GetEarliestEpoch(l *list.List, name string, status []string) (*ObjectMessage) {
	earliest := 0
	var result *ObjectMessage
	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(ObjectMessage)
		if *o.ObjId.ObjName != name {
			continue
		}
		if o.ObjId.ObjEpoch == nil {
			continue
		}
		if result == nil {
			result = &o
			earliest = int(*o.ObjId.ObjEpoch)
			continue
		}
		if earliest == 0 || int(*o.ObjId.ObjEpoch) < earliest {
			earliest = int(*o.ObjId.ObjEpoch)
			result = &o
		}
	}
	return result 
}

// Marshal protected objects and save them in a file.
// nil is error return
func SaveProtectedObjects(l *list.List, file string) error {
	var po_store ProtectedObjectStoreMessage

	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(ProtectedObjectMessage)
		p := new(ProtectedObjectMessage)
		p.ProtectedObjId.ObjName = o.ProtectedObjId.ObjName
		p.ProtectedObjId.ObjEpoch = o.ProtectedObjId.ObjEpoch
		p.ProtectorObjId.ObjName = o.ProtectorObjId.ObjName
		p.ProtectorObjId.ObjEpoch = o.ProtectorObjId.ObjEpoch
		p.Blob= o.Blob
		po_store.ProtectedObjects = append(po_store.ProtectedObjects, p)
	}
	b, err := proto.Marshal(&po_store)
	if err != nil {
		return err
	}
	ioutil.WriteFile(file, b, 0644)
	return nil
}

// Marshal nodes and save them in a file.
// nil is error return
func SaveNodes(l *list.List, file string) error {
	var node_store NodeStoreMessage

	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(NodeMessage)
		p := new(NodeMessage)
		p.ProtectedObjId.ObjName = o.ProtectedObjId.ObjName
		p.ProtectedObjId.ObjEpoch = o.ProtectedObjId.ObjEpoch
		p.ProtectorObjId.ObjName = o.ProtectorObjId.ObjName
		p.ProtectorObjId.ObjEpoch = o.ProtectorObjId.ObjEpoch
		node_store.NodeObjects = append(node_store.NodeObjects, p)
	}
	b, err := proto.Marshal(&node_store)
	if err != nil {
		return err
	}
	ioutil.WriteFile(file, b, 0644)
	return nil
}

// Marshal objects and save them in a file.
// nil is error return
func SaveObjects(l *list.List, file string) error {
	var o_store ObjectStoreMessage

	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(ObjectMessage)
		p := new(ObjectMessage)
		p.ObjId = new(ObjectIdMessage)
		p.ObjId.ObjName = o.ObjId.ObjName
		p.ObjId.ObjEpoch = o.ObjId.ObjEpoch
		p.ObjType = o.ObjType
		p.ObjStatus = o.ObjStatus
		p.NotBefore = o.NotBefore
		p.NotAfter = o.NotAfter
		p.ObjVal = o.ObjVal
		o_store.Objects = append(o_store.Objects, p)
	}
	b, err := proto.Marshal(&o_store)
	if err != nil {
		return nil
	}
	ioutil.WriteFile(file, b, 0644)
	return nil
}

// Read and unmarshal an protected object file.
func LoadProtectedObjects(file string) (*list.List) {
	var po_store ProtectedObjectStoreMessage

	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return nil
	}
	err = proto.Unmarshal(buf, &po_store)
	if err != nil {
		return nil
	}
	l := list.New()
	for _, v := range(po_store.ProtectedObjects) {
		o := new(ProtectedObjectMessage)
		o.ProtectorObjId.ObjName = v.ProtectorObjId.ObjName
		o.ProtectorObjId.ObjEpoch = v.ProtectorObjId.ObjEpoch
		o.ProtectedObjId.ObjName = v.ProtectedObjId.ObjName
		o.ProtectedObjId.ObjEpoch = v.ProtectedObjId.ObjEpoch
		o.Blob = v.Blob
		l.PushFront(*o)
	}
	return l
}

// Read and unmarshal a node file.
func LoadNodes(file string) (*list.List) {
	var node_store NodeStoreMessage

	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return nil
	}
	err = proto.Unmarshal(buf, &node_store)
	if err != nil {
		return nil
	}
	l := list.New()
	for _, v := range(node_store.NodeObjects) {
		o := new(NodeMessage)
		o.ProtectedObjId.ObjName = v.ProtectedObjId.ObjName
		o.ProtectedObjId.ObjEpoch = v.ProtectedObjId.ObjEpoch
		o.ProtectorObjId.ObjName = v.ProtectorObjId.ObjName
		o.ProtectorObjId.ObjEpoch = v.ProtectorObjId.ObjEpoch
		l.PushFront(*o)
	}
	return l
}

// Read and unmarshal an object file.
func LoadObjects(file string) (*list.List) {
	var o_store ObjectStoreMessage

	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return nil
	}
	err = proto.Unmarshal(buf, &o_store)
	if err != nil {
		return nil
	}
	l := list.New()
	for _, v := range(o_store.Objects) {
		o := new(ObjectMessage)
		o.ObjId = new(ObjectIdMessage)
		o.ObjId.ObjName = v.ObjId.ObjName
		o.ObjId.ObjEpoch = v.ObjId.ObjEpoch

		o.ObjType = v.ObjType
		o.ObjStatus = v.ObjStatus
		o.NotBefore = v.NotBefore
		o.NotAfter = v.NotAfter
		o.ObjVal = v.ObjVal
		l.PushFront(*o)
	}
	return l
}

// Create, marshal and encrypt a protected object blob protecting obj.
func MakeProtectedObject(obj ObjectMessage, protectorName string, protectorEpoch int32,
		protectorKeys []byte) (*ProtectedObjectMessage, error) {
	p := new(ProtectedObjectMessage)
	p.ProtectedObjId = new(ObjectIdMessage)
	p.ProtectorObjId = new(ObjectIdMessage)
	p.ProtectedObjId.ObjName = obj.ObjId.ObjName
	p.ProtectedObjId.ObjEpoch =obj.ObjId.ObjEpoch
	p.ProtectorObjId.ObjName = &protectorName
	p.ProtectorObjId.ObjEpoch = &protectorEpoch
	unencrypted, err := proto.Marshal(&obj)
	if err != nil {
		return nil, errors.New("Can't make Protected Object")
	}
	encrypted, err := tpm2.Protect(protectorKeys, unencrypted)
	if err != nil {
		return nil, errors.New("Can't Protect Object")
	}
	p.Blob = encrypted
	return p, nil
}

// Decrypt and unmarshal a protected object blob
func RecoverProtectedObject(obj *ProtectedObjectMessage, protectorKeys []byte) (*ObjectMessage, error) {
	p := new(ObjectMessage)
	unencrypted, err := tpm2.Unprotect(protectorKeys, obj.Blob)
	if err != nil {
		return nil, errors.New("Can't make Unprotect Object")
	}
	err = proto.Unmarshal(unencrypted, p)
	if err != nil {
		return nil, errors.New("Can't Unmarshal Object")
	}
	return p, nil
}

// Make a node
func MakeNode(protectorName string, protectorEpoch int32, protectedName string,
	protectedEpoch int32) (*NodeMessage) {
	protector := &ObjectIdMessage {
		ObjName: &protectorName,
		ObjEpoch: &protectorEpoch,
	}
	protected := &ObjectIdMessage {
		ObjName: &protectedName,
		ObjEpoch: &protectedEpoch,
	}
	nodeMsg := new(NodeMessage)
	nodeMsg.ProtectedObjId = protected
	nodeMsg.ProtectorObjId = protector
	return nodeMsg
}

// Is object the right type, have the right status and in it's validity period?
func IsValid(obj ObjectMessage, statuses []string, types []string) (bool) {
	// if object is not active or the dates are wrong, return false
	if !stringMatch(obj.ObjStatus, statuses) {
		return false
	}
	if !stringMatch(obj.ObjType, types) {
		return false
	}
	tb, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", *obj.NotBefore)
	if err != nil {
		return false
	}
	ta, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", *obj.NotAfter)
	if err != nil {
		return false
	}
	tn := time.Now()
	if tb.After(tn) || ta.Before(tn) {
		return false
	}
	return true
}

// Construct chain of protector objects for (nameNode, epochNode)
// Stops when there are no protectors for top object
func ConstructProtectorChain(obj_list *list.List, nameNode string, epochNode int32,
	statuses []string, types []string, nameTop *string, epochTop *int32, seen_list *list.List,
	node_list *list.List) (*list.List, error) {

	if nameTop != nil &&  *nameTop == nameNode {
		if epochTop == nil || *epochTop == epochNode {
			return seen_list, nil
		}
	}
	pl := FindProtectedNodes(node_list, nameNode, epochNode)
	if pl == nil {
		return nil, errors.New("ProtectedNode error")
	}
	for e := pl.Front(); e != nil; e = e.Next() {
		o := e.Value.(NodeMessage)
		t := FindObject(seen_list, *o.ProtectorObjId.ObjName,
                        *o.ProtectorObjId.ObjEpoch, statuses, types)
		if t != nil {
			return nil, errors.New("Circular list")
		}
		t = FindObject(obj_list, *o.ProtectorObjId.ObjName,
			*o.ProtectorObjId.ObjEpoch, statuses, types)
		if t == nil {
			return seen_list, nil
		}
		if !IsValid(*t, statuses, types) {
			continue
		}
		AddObject(seen_list, *t)
		return ConstructProtectorChain(obj_list,
			*o.ProtectorObjId.ObjName, *o.ProtectorObjId.ObjEpoch,
			statuses, types, nameTop, epochTop, seen_list, node_list)
	}
	return seen_list, nil
}

// Construct chain of protector objects for (nameNode, epochNode)
//	Chain must terminate with an object from the base list
func ConstructProtectorChainFromBase(obj_list *list.List, nameNode string, epochNode int32,
	statuses []string, types []string,
	base_list *list.List, seen_list *list.List, node_list *list.List) (*list.List, error) {

	// if object is in base list, we're done
	for e := base_list.Front(); e != nil; e = e.Next() {
		o := e.Value.(ObjectIdMessage)
		if *o.ObjName == nameNode {
			if o.ObjEpoch == nil  || *o.ObjEpoch == epochNode {
				return seen_list, nil
			}
		}
	}

	pl := FindProtectedNodes(node_list, nameNode, epochNode)
	if pl == nil {
		return nil, errors.New("ProtectedNode error")
	}
	for e := pl.Front(); e != nil; e = e.Next() {
		o := e.Value.(NodeMessage)
		t := FindObject(seen_list, *o.ProtectorObjId.ObjName,
                        *o.ProtectorObjId.ObjEpoch, statuses, types)
		if t != nil {
			return nil, errors.New("Circular list")
		}
		t = FindObject(obj_list, *o.ProtectorObjId.ObjName,
			*o.ProtectorObjId.ObjEpoch, statuses, types)
		if !IsValid(*t, statuses, types) {
			continue
		}
		AddObject(seen_list, *t)
		return ConstructProtectorChainFromBase(obj_list,
			*o.ProtectorObjId.ObjName, *o.ProtectorObjId.ObjEpoch,
			statuses, types, base_list, seen_list, node_list)
	}
	return nil, errors.New("Can't find any base value")
}
