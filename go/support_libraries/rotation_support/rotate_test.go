// Copyright (c) 2016, Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License")
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

package rotation_support

import (
	"container/list"
	"fmt"
	"testing"
	"time"

	"github.com/jlmucb/cloudproxy/go/support_libraries/protected_objects"
)

func TestAddKeyEpoch(t *testing.T) {

	obj_type := "file"
	status := "active"
	nb := time.Now()
	validFor := 365 * 24 * time.Hour
	na := nb.Add(validFor)

	obj_1, err := protected_objects.CreateObject("/jlm/file/file1", 1,
		&obj_type, &status, &nb, &na, nil)
	if err != nil {
		t.Fatal("Can't create object")
	}
	fmt.Printf("Obj: %s\n", *obj_1.NotBefore)
	obj_type = "key"
	obj_2, _ := protected_objects.CreateObject("/jlm/key/key1", 1,
		&obj_type, &status, &nb, &na, nil)
	obj_3, _ := protected_objects.CreateObject("/jlm/key/key2", 1,
		&obj_type, &status, &nb, &na, nil)

	// add them to object list
	obj_list := list.New()
	err = protected_objects.AddObject(obj_list, *obj_1)
	if err != nil {
		t.Fatal("Can't add object")
	}
	_ = protected_objects.AddObject(obj_list, *obj_2)
	_ = protected_objects.AddObject(obj_list, *obj_3)

	newkey := []byte{
		0xff, 0xfe, 0xff, 0xfe, 0xff, 0xfe, 0xff, 0xfe,
		0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02,
		0x07, 0x08, 0x07, 0x08, 0x07, 0x08, 0x07, 0x08,
		0xa6, 0xa5, 0xa6, 0xa5, 0xa6, 0xa5, 0xa6, 0xa5}

	oldkeyobj, newkeyobj, err := AddNewKeyEpoch(obj_list, "/jlm/key/key1",
		"key", "active", "active", nb.String(), na.String(), newkey)
	if err != nil {
		t.Fatal("Can't add new key epoch")
	}
	fmt.Printf("\n\n")
	if oldkeyobj == nil {
		fmt.Printf("No old key object\n")
	} else {
		fmt.Printf("Old key object:\n")
		protected_objects.PrintObject(oldkeyobj)
	}
	fmt.Printf("\n\n")
	if newkeyobj == nil {
		t.Fatal("Can't new key object is nil")
	}
	fmt.Printf("New key object:\n")
	protected_objects.PrintObject(newkeyobj)
	fmt.Printf("\n")

	oldkeyobj, newkeyobj, err = AddNewKeyEpoch(obj_list, "/jlm/key/key4",
		"key", "active", "active", nb.String(), na.String(), newkey)
	if err != nil {
		t.Fatal("Can't add new key epoch")
	}
	fmt.Printf("\n\n")
	if oldkeyobj == nil {
		fmt.Printf("No old key object\n")
	} else {
		fmt.Printf("Old key object:\n")
		protected_objects.PrintObject(oldkeyobj)
	}
	fmt.Printf("\n\n")
	if newkeyobj == nil {
		t.Fatal("Can't new key object is nil")
	}
	fmt.Printf("New key object:\n")
	protected_objects.PrintObject(newkeyobj)
	fmt.Printf("\n")
}

func TestAddAndRotate(t *testing.T) {

	obj_type := "file"
	status := "active"
	nb := time.Now()
	validFor := 365 * 24 * time.Hour
	na := nb.Add(validFor)

	protectorKeys := []byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
	}

	obj_1, err := protected_objects.CreateObject("/jlm/file/file1", 1,
		&obj_type, &status, &nb, &na, nil)
	if err != nil {
		t.Fatal("Can't create object")
	}
	fmt.Printf("Obj: %s\n", *obj_1.NotBefore)
	obj_type = "key"
	obj_2, _ := protected_objects.CreateObject("/jlm/key/key1", 1,
		&obj_type, &status, &nb, &na, protectorKeys)
	obj_3, _ := protected_objects.CreateObject("/jlm/key/key2", 1,
		&obj_type, &status, &nb, &na, protectorKeys)

	// add them to object list
	obj_list := list.New()
	err = protected_objects.AddObject(obj_list, *obj_1)
	if err != nil {
		t.Fatal("Can't add object")
	}
	_ = protected_objects.AddObject(obj_list, *obj_2)
	_ = protected_objects.AddObject(obj_list, *obj_3)

	p_obj_1, err := protected_objects.MakeProtectedObject(*obj_1, "/jlm/key/key1", 1, protectorKeys)
	if err != nil {
		t.Fatal("Can't make protected object")
	}
	if p_obj_1 == nil {
		t.Fatal("Bad protected object")
	}

	p_obj_2, err := protected_objects.MakeProtectedObject(*obj_2, "/jlm/key/key2", 1, protectorKeys)
	if err != nil {
		t.Fatal("Can't make protected object")
	}
	if p_obj_2 == nil {
		t.Fatal("Bad protected object")
	}

	protected_obj_list := list.New()
	err = protected_objects.AddProtectedObject(protected_obj_list, *p_obj_1)
	if err != nil {
		t.Fatal("Can't add protected object")
	}
	err = protected_objects.AddProtectedObject(protected_obj_list, *p_obj_2)
	if err != nil {
		t.Fatal("Can't add protected object")
	}

	fmt.Printf("\n\n")
	fmt.Printf("Initial Objects\n")
	for e := obj_list.Front(); e != nil; e = e.Next() {
		o := e.Value.(protected_objects.ObjectMessage)
		protected_objects.PrintObject(&o)
	}
	fmt.Printf("\n\nInitial protected objects\n")
	for e := protected_obj_list.Front(); e != nil; e = e.Next() {
		o := e.Value.(protected_objects.ProtectedObjectMessage)
		protected_objects.PrintProtectedObject(&o)
	}
	fmt.Printf("\n\n")

	newkey := []byte{
		0xff, 0xfe, 0xff, 0xfe, 0xff, 0xfe, 0xff, 0xfe,
		0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02,
		0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02,
		0x07, 0x08, 0x07, 0x08, 0x07, 0x08, 0x07, 0x08,
		0x07, 0x08, 0x07, 0x08, 0x07, 0x08, 0x07, 0x08,
		0xa6, 0xa5, 0xa6, 0xa5, 0xa6, 0xa5, 0xa6, 0xa5}

	new_obj, err := AddAndRotateNewKeyEpoch("/jlm/key/key2", "key", "active", "active",
		nb.String(), na.String(), newkey, obj_list, protected_obj_list)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		t.Fatal("Can't AddAndRotateNewKeyEpoch")
	}
	fmt.Printf("\n\n")
	fmt.Printf("New key: %s, %d\n", new_obj.ObjId.ObjName, new_obj.ObjId.ObjEpoch)
	fmt.Printf("\n\n")
	fmt.Printf("Protected objects\n")
	for e := protected_obj_list.Front(); e != nil; e = e.Next() {
		o := e.Value.(protected_objects.ProtectedObjectMessage)
		protected_objects.PrintProtectedObject(&o)
	}
	fmt.Printf("\n\n")
	fmt.Printf("Objects\n")
	for e := obj_list.Front(); e != nil; e = e.Next() {
		o := e.Value.(protected_objects.ObjectMessage)
		protected_objects.PrintObject(&o)
	}
	fmt.Printf("\n\n")
	// Check we can open protected object with new protector
	protected_kids := protected_objects.FindProtectedObjects(protected_obj_list, *new_obj.ObjId.ObjName,
		*new_obj.ObjId.ObjEpoch)
	if err != nil {
		t.Fatal("Can't FindProtected kids")
	}
	e := protected_kids.Front()
	o := e.Value.(protected_objects.ProtectedObjectMessage)
	obj, err := protected_objects.RecoverProtectedObject(&o, new_obj.ObjVal)
	if err != nil || obj == nil {
		t.Fatal("Can't recover first kid")
	}
	fmt.Printf("\n\nRecovered:\n")
	protected_objects.PrintObject(obj)
}
