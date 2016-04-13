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

func AddObject(l *list.List, obj interface{}) error {
	l.PushFront(obj)
	return nil
}

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

func FindObject(l *list.List, name string, epoch int32) (*ObjectMessage) {
	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(ObjectMessage)
		if epoch != 0 && epoch != *o.ObjId.ObjEpoch {
			continue
		}
		if name == *o.ObjId.ObjName {
			return &o
		}
        }
	return nil
}

func GetLatestEpoch(l *list.List, name string, epoch int32) (*ObjectMessage) {
	return nil
}

func GetEarliestEpoch(l *list.List, name string, epoch int32) (*ObjectMessage) {
	return nil
}

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
		PrintObject(v)
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

func AddNode(l *list.List, obj interface{}) error {
	l.PushFront(obj)
	return nil
}
