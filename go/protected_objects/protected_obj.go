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
	"fmt"
	"io/ioutil"
	"time"

	"github.com/golang/protobuf/proto"
)

func PrintObject(obj *ObjectMessage) {
	fmt.Printf("Object %s, epoch %d\n", *obj.ObjId.ObjName, *obj.ObjId.ObjEpoch)
	fmt.Printf("\ttype %s, status %s, notbefore: %s, notafter: %s\n", *obj.ObjType,
		*obj.ObjStatus, *obj.NotBefore, *obj.NotAfter)
	// ObjVal
}

func PrintProtectedObject(obj *ProtectedObjectMessage) {
	fmt.Printf("ProtectedObject %s, epoch %d\n", *obj.ProtectedObj.ObjId.ObjName,
		 *obj.ProtectedObj.ObjId.ObjEpoch)
	 fmt.Printf("\ttype %s, status %s, notbefore: %s, notafter: %s\n", *obj.ProtectedObj.ObjType,
		*obj.ProtectedObj.ObjStatus, *obj.ProtectedObj.NotBefore, *obj.ProtectedObj.NotAfter)
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

func StoreObject(l *list.List, obj interface{}) error {
	l.PushFront(obj)
	return nil
}

func DeleteObject(l *list.List, name string, epoch int32) error {
	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(*ObjectMessage)
		if *o.ObjId.ObjName == name && *o.ObjId.ObjEpoch == epoch {
			l.Remove(e)
			break;
		}
	}
	return nil
}

func DeleteProtectedObject(l *list.List, name string, epoch int32) error {
	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(*ProtectedObjectMessage)
		if *o.ProtectedObj.ObjId.ObjName == name && *o.ProtectedObj.ObjId.ObjEpoch == epoch {
			l.Remove(e)
			break;
		}
	}
	return nil
}

func FindProtectedObject(l *list.List, name string, epoch int32) (*list.List) {
	r := list.New()

	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(*ProtectedObjectMessage)
		if epoch != 0 && epoch != *o.ProtectedObj.ObjId.ObjEpoch {
			continue
		}
		if name == *o.ProtectedObj.ObjId.ObjName {
			r.PushFront(o)
		}
        }
	return r
}

func FindProtectorObject(l *list.List, name string, epoch int32) (*list.List) {
	r := list.New()

	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(*ProtectedObjectMessage)
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
		o := e.Value.(*ObjectMessage)
		if epoch != 0 && epoch != *o.ObjId.ObjEpoch {
			continue
		}
		if name == *o.ObjId.ObjName {
			return o
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
		o := e.Value.(*ProtectedObjectMessage)
		p := new(ProtectedObjectMessage)
		// p.ProtectorObjId = new(ObjectIdMessage)
		p.ProtectorObjId.ObjName = o.ProtectorObjId.ObjName
		p.ProtectorObjId.ObjEpoch = o.ProtectorObjId.ObjEpoch
		p.ProtectedObj.ObjId.ObjName = o.ProtectedObj.ObjId.ObjName
		p.ProtectedObj.ObjId.ObjEpoch = o.ProtectedObj.ObjId.ObjEpoch
		p.ProtectedObj.ObjType = o.ProtectedObj.ObjType
		p.ProtectedObj.ObjStatus = o.ProtectedObj.ObjStatus
		p.ProtectedObj.NotBefore = o.ProtectedObj.NotBefore
		p.ProtectedObj.NotAfter = o.ProtectedObj.NotAfter
		p.ProtectedObj.ObjVal = o.ProtectedObj.ObjVal
		po_store.ProtectedObjects = append(po_store.ProtectedObjects, p)
	}
	b, err := proto.Marshal(&po_store)
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
		o := e.Value.(*ObjectMessage)
		p := new(ObjectMessage)
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
		o.ProtectedObj.ObjId.ObjName = v.ProtectedObj.ObjId.ObjName
		o.ProtectedObj.ObjId.ObjEpoch = v.ProtectedObj.ObjId.ObjEpoch

		o.ProtectedObj.ObjType = v.ProtectedObj.ObjType
		o.ProtectedObj.ObjStatus = v.ProtectedObj.ObjStatus
		o.ProtectedObj.NotBefore = v.ProtectedObj.NotBefore
		o.ProtectedObj.NotAfter = v.ProtectedObj.NotAfter
		o.ProtectedObj.ObjVal = v.ProtectedObj.ObjVal
		l.PushFront(o)
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
		o.ObjId.ObjName = v.ObjId.ObjName
		o.ObjId.ObjEpoch = v.ObjId.ObjEpoch

		o.ObjType = v.ObjType
		o.ObjStatus = v.ObjStatus
		o.NotBefore = v.NotBefore
		o.NotAfter = v.NotAfter
		o.ObjVal = v.ObjVal
		l.PushFront(o)
	}
	return l 
}

