// Copyright (c) 2016, Google Inc. All rights reserved.
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

package rotation_support

import (
	"fmt"
	"container/list"
	"testing"
	"time"

	"github.com/jlmucb/cloudproxy/go/support_libraries/protected_objects"
	"github.com/jlmucb/cloudproxy/go/support_libraries/rotation_support"
)

func TestAddKeyEpoch(t *testing.T) {

	obj_type := "file"
	status := "active"
	nb := time.Now()
	validFor := 365*24*time.Hour
	na := nb.Add(validFor)

	obj_1, err := protected_objects.CreateObject("/jlm/file/file1", 1,
		&obj_type, &status, &nb, &na, nil)
	if err != nil {
		t.Fatal("Can't create object")
	}
	fmt.Printf("Obj: %s\n", *obj_1.NotBefore)
	obj_type = "key"
	obj_2, _:= protected_objects.CreateObject("/jlm/key/key1", 1,
		&obj_type, &status, &nb, &na, nil)
	obj_3, _:= protected_objects.CreateObject("/jlm/key/key2", 1,
		&obj_type, &status, &nb, &na, nil)

	// add them to object list
	obj_list := list.New()
	err = protected_objects.AddObject(obj_list, *obj_1)
	if err != nil {
		t.Fatal("Can't add object")
	}
	_ = protected_objects.AddObject(obj_list, *obj_2)
	_ = protected_objects.AddObject(obj_list, *obj_3)

	newkey := []byte{ 0xff, 0xfe, 0xff, 0xfe, 0xff, 0xfe, 0xff, 0xfe, 
			  0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02,
			  0x07, 0x08, 0x07, 0x08, 0x07, 0x08, 0x07, 0x08,
			  0xa6, 0xa5, 0xa6, 0xa5, 0xa6, 0xa5, 0xa6, 0xa5,}

	oldkeyobj, newkeyobj, err := rotation_support.AddNewKeyEpoch(obj_list, "/jlm/key/key1",
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

	oldkeyobj, newkeyobj, err = rotation_support.AddNewKeyEpoch(obj_list, "/jlm/key/key4",
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
/*
	// Add three objects: a file and two keys
	obj_type := "file"
	status := "active"
	notBefore := time.Now()
	validFor := 365*24*time.Hour
	notAfter := notBefore.Add(validFor)

	obj_1, err := protected_objects.CreateObject("/jlm/file/file1", 1,
		&obj_type, &status, &notBefore, &notAfter, nil)
	if err != nil {
		t.Fatal("Can't create object")
	}
	fmt.Printf("Obj: %s\n", *obj_1.NotBefore)
	obj_type = "key"
	obj_2, _:= protected_objects.CreateObject("/jlm/key/key1", 1,
		&obj_type, &status, &notBefore, &notAfter, nil)
	obj_3, _:= protected_objects.CreateObject("/jlm/key/key2", 1,
		&obj_type, &status, &notBefore, &notAfter, nil)

	// add them to object list
	obj_list := list.New()
	err = protected_objects.AddObject(obj_list, *obj_1)
	if err != nil {
		t.Fatal("Can't add object")
	}
	_ = protected_objects.AddObject(obj_list, *obj_2)
	_ = protected_objects.AddObject(obj_list, *obj_3)

	// Find object test
	o3 := protected_objects.FindObject(obj_list, *obj_1.ObjId.ObjName, *obj_1.ObjId.ObjEpoch, nil, nil)
	if o3 == nil {
		t.Fatal("Can't find object")
	}
	fmt.Printf("Found object\n")
	protected_objects.PrintObject(o3)

	// Make a protected object
	protectorKeys := []byte{
		0,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf,
		0,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf,
	}
	p_obj_1, err := protected_objects.MakeProtectedObject(*obj_1, "/jlm/key/key1", 1, protectorKeys)
	if err != nil {
		t.Fatal("Can't make protected object")
	}
	if p_obj_1 == nil {
		t.Fatal("Bad protected object")
	}
	protected_objects.PrintProtectedObject(p_obj_1)

	p_obj_2, err := protected_objects.RecoverProtectedObject(p_obj_1, protectorKeys)
	if err != nil {
		t.Fatal("Can't recover protected object")
	}
*/
	// ChangeObjectStatus(l *list.List, name_obj string, epoch int, new_status string) error
	// RevokeObject(l *list.List, name_obj string, epoch int) (error)
	// AddNewKeyEpoch(l *list.List, name_obj string, obj_type string, existing_status string, new_status string,
        //   notBefore string, notAfter string, value []byte)
	//   (*protected_objects.ObjectMessage, *protected_objects.ObjectMessage, error)
	// AddAndRotateNewKeyEpoch(name_obj string,  obj_type string, existing_status string,
        //      new_status string, notBefore string, notAfter string,
        //      value []byte, node_list *list.List, obj_list *list.List,
        //      protected_obj_list *list.List) (int, error)
	// reencrypt the things it supports
	// check the encryption
}

