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
	"time"

	// "github.com/golang/protobuf/proto"
)

func PrintObject(obj *ObjectMessage) {
	fmt.Printf("Object %s, epoch %d\n", *obj.ObjId.ObjName, *obj.ObjId.ObjEpoch)
	fmt.Printf("\ttype %s, status %s, notbefore: %s, notafter: %s\n", *obj.ObjType,
		*obj.ObjStatus, *obj.NotBefore, *obj.NotAfter)
	// ObjVal
}

func PrintProtectedObject(obj *ProtectedObjectMessage) {
	fmt.Printf("ProtectedObject %s, epoch %d\n", *obj.ProtectedObjId.ObjId.ObjName,
		 *obj.ProtectedObjId.ObjId.ObjEpoch)
	 fmt.Printf("\ttype %s, status %s, notbefore: %s, notafter: %s\n", *obj.ProtectedObjId.ObjType,
		*obj.ProtectedObjId.ObjStatus, *obj.ProtectedObjId.NotBefore, *obj.ProtectedObjId.NotAfter)
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

func DeleteObject(l *list.List, obj interface{}) error {
	return nil
}

func DeleteProtectedObject(l *list.List, obj interface{}) error {
	return nil
}

func FindProtectedObject(l *list.List, name string, epoch int32) (*list.List) {
	r := list.New()

	for e := l.Front(); e != nil; e = e.Next() {
		o := e.Value.(*ProtectedObjectMessage)
		if epoch != 0 && epoch != *o.ProtectedObjId.ObjId.ObjEpoch {
			continue
		}
		if name == *o.ProtectedObjId.ObjId.ObjName {
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
	// var po_store ProtectedObjectStoreMessage
	return nil
}

func SaveObjects(l *list.List, file string) error {
	// var o_store ObjectStoreMessage
	return nil
}

func LoadProtectedObjects(file string) (*list.List) {
	return nil
}

func LoadObjects(file string) (*list.List) {
	return nil
}

