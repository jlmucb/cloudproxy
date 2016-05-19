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

package protected_objects

import (
	"container/list"
	"fmt"
	"testing"
	"time"
	// "github.com/jlmucb/cloudproxy/go/tpm2"
	// "github.com/golang/protobuf/proto"
)

func TestTime(t *testing.T) {
	ttb := time.Now()
	ttn := time.Now()
	tta := time.Now()
	tb, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", ttb.String())
	if err != nil {
		t.Fatal("Can't parse time before\n")
	}
	ta, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", tta.String())
	if err != nil {
		t.Fatal("Can't parse time after\n")
	}
	fmt.Printf("tb: %s, tn: %s, ta: %s\n", tb.String(), ttn.String(), ta.String())
	if tb.After(ttn) {
		t.Fatal("Time after fails\n")
	}
	if ta.Before(ttn) {
		t.Fatal("Time before fails\n")
	}
}

func TestBasicObject(t *testing.T) {

	// Add three objects: a file and two keys
	obj_type := "file"
	status := "active"
	notBefore := time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	obj_1, err := CreateObject("/jlm/file/file1", 1,
		&obj_type, &status, &notBefore, &notAfter, nil)
	if err != nil {
		t.Fatal("Can't create object")
	}
	fmt.Printf("Obj: %s\n", *obj_1.NotBefore)
	obj_type = "key"
	obj_2, _ := CreateObject("/jlm/key/key1", 1,
		&obj_type, &status, &notBefore, &notAfter, nil)
	obj_3, _ := CreateObject("/jlm/key/key2", 1,
		&obj_type, &status, &notBefore, &notAfter, nil)

	// add them to object list
	obj_list := list.New()
	err = AddObject(obj_list, *obj_1)
	if err != nil {
		t.Fatal("Can't add object")
	}
	_ = AddObject(obj_list, *obj_2)
	_ = AddObject(obj_list, *obj_3)

	// Find object test
	o3 := FindObject(obj_list, *obj_1.ObjId.ObjName, *obj_1.ObjId.ObjEpoch, nil, nil)
	if o3 == nil {
		t.Fatal("Can't find object")
	}
	fmt.Printf("Found object\n")
	PrintObject(o3)

	// Make a protected object
	protectorKeys := []byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
	}
	p_obj_1, err := MakeProtectedObject(*obj_1, "/jlm/key/key1", 1, protectorKeys)
	if err != nil {
		t.Fatal("Can't make protected object")
	}
	if p_obj_1 == nil {
		t.Fatal("Bad protected object")
	}
	PrintProtectedObject(p_obj_1)

	p_obj_2, err := MakeProtectedObject(*obj_2, "/jlm/key/key2", 1, protectorKeys)
	if err != nil {
		t.Fatal("Can't make protected object")
	}
	if p_obj_2 == nil {
		t.Fatal("Bad protected object")
	}
	PrintProtectedObject(p_obj_2)

	p_obj_3, err := RecoverProtectedObject(p_obj_1, protectorKeys)
	if err != nil {
		t.Fatal("Can't recover protected object")
	}
	if *obj_1.ObjId.ObjName != *p_obj_3.ObjId.ObjName {
		t.Fatal("objects don't match")
	}

	protected_obj_list := list.New()
	_ = AddProtectedObject(protected_obj_list, *p_obj_1)
	_ = AddProtectedObject(protected_obj_list, *p_obj_2)

	pr_list1 := FindProtectorObjects(protected_obj_list, "/jlm/key/key1", 1)
	if pr_list1 == nil {
		t.Fatal("FindProtectorObjects fails")
	}
	fmt.Printf("Protecting:\n")
	for e := pr_list1.Front(); e != nil; e = e.Next() {
		o := e.Value.(ProtectedObjectMessage)
		PrintProtectedObject(&o)
	}
	fmt.Printf("\n")
	fmt.Printf("Protected:\n")
	pr_list2 := FindProtectedObjects(protected_obj_list, "/jlm/key/key1", 1)
	if pr_list2 == nil {
		t.Fatal("FindProtectedObjects fails")
	}
	for e := pr_list2.Front(); e != nil; e = e.Next() {
		o := e.Value.(ProtectedObjectMessage)
		PrintProtectedObject(&o)
	}
	fmt.Printf("\n")
}

func TestEarliestandLatest(t *testing.T) {

	// Add three objects: a file and two keys
	obj_type := "key"
	status := "active"
	notBefore := time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	obj_1, _ := CreateObject("/jlm/key/key1", 1,
		&obj_type, &status, &notBefore, &notAfter, nil)
	obj_2, _ := CreateObject("/jlm/key/key1", 2,
		&obj_type, &status, &notBefore, &notAfter, nil)

	// add them to object list
	obj_list := list.New()
	err := AddObject(obj_list, *obj_1)
	if err != nil {
		t.Fatal("Can't add object")
	}
	_ = AddObject(obj_list, *obj_2)

	statuses := []string{"active"}
	result := GetEarliestEpoch(obj_list, "/jlm/key/key1", statuses)
	if result == nil {
		t.Fatal("Can't get earliest epoch")
	}
	if *result.ObjId.ObjName != "/jlm/key/key1" ||
		result.ObjId.ObjEpoch == nil || *result.ObjId.ObjEpoch != 1 {
		t.Fatal("Earliest epoch failed")
	}

	result = GetLatestEpoch(obj_list, "/jlm/key/key1", statuses)
	if result == nil {
		t.Fatal("Can't get latest epoch")
	}
	if *result.ObjId.ObjName != "/jlm/key/key1" ||
		result.ObjId.ObjEpoch == nil || *result.ObjId.ObjEpoch != 2 {
		PrintObject(result)
		t.Fatal("Latest epoch failed")
	}
}

func TestSaveAndRestore(t *testing.T) {

	// Add three objects: a file and two keys
	obj_type := "file"
	status := "active"
	notBefore := time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	obj_1, err := CreateObject("/jlm/file/file1", 1,
		&obj_type, &status, &notBefore, &notAfter, nil)
	if err != nil {
		t.Fatal("Can't create object")
	}
	fmt.Printf("Obj: %s\n", *obj_1.NotBefore)
	obj_type = "key"
	obj_2, _ := CreateObject("/jlm/key/key1", 1,
		&obj_type, &status, &notBefore, &notAfter, nil)
	obj_3, _ := CreateObject("/jlm/key/key2", 1,
		&obj_type, &status, &notBefore, &notAfter, nil)

	// add them to object list
	obj_list := list.New()
	err = AddObject(obj_list, *obj_1)
	if err != nil {
		t.Fatal("Can't add object")
	}
	_ = AddObject(obj_list, *obj_2)
	_ = AddObject(obj_list, *obj_3)

	err = SaveObjects(obj_list, "tmptest/s1")
	if err != nil {
		t.Fatal("Can't save objects")
	}
	r := LoadObjects("tmptest/s1")
	if r == nil {
		t.Fatal("Can't Load objects")
	}

	if obj_list.Len() != r.Len() {
		t.Fatal("recovered object list has different size")
	}

	er := obj_list.Front()
	for eo := obj_list.Front(); eo != nil; eo = eo.Next() {
		oo := eo.Value.(ObjectMessage)
		or := er.Value.(ObjectMessage)
		if *oo.ObjId.ObjName != *or.ObjId.ObjName {
			t.Fatal("recovered name doesn't match")
		}
		if *oo.ObjId.ObjEpoch != *or.ObjId.ObjEpoch {
			t.Fatal("recovered object doesn't match")
		}
		er = er.Next()
	}
}

func TestConstructChain(t *testing.T) {

	// Add three objects: a file and two keys
	obj_type := "file"
	status := "active"
	notBefore := time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	obj_1, err := CreateObject("/jlm/file/file1", 1,
		&obj_type, &status, &notBefore, &notAfter, nil)
	if err != nil {
		t.Fatal("Can't create object")
	}
	fmt.Printf("Obj: %s\n", *obj_1.NotBefore)
	obj_type = "key"
	obj_2, _ := CreateObject("/jlm/key/key1", 1,
		&obj_type, &status, &notBefore, &notAfter, nil)
	obj_3, _ := CreateObject("/jlm/key/key2", 1,
		&obj_type, &status, &notBefore, &notAfter, nil)

	// add them to object list
	obj_list := list.New()
	err = AddObject(obj_list, *obj_1)
	if err != nil {
		t.Fatal("Can't add object")
	}
	_ = AddObject(obj_list, *obj_2)
	_ = AddObject(obj_list, *obj_3)

	protected_obj_list := list.New()

	// Make a protected object
	protectorKeys := []byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
	}
	p_obj_1, err := MakeProtectedObject(*obj_1, "/jlm/key/key1", 1, protectorKeys)
	if err != nil {
		t.Fatal("Can't make protected object")
	}
	if p_obj_1 == nil {
		t.Fatal("Bad protected object")
	}
	PrintProtectedObject(p_obj_1)

	p_obj_2, err := MakeProtectedObject(*obj_2, "/jlm/key/key2", 1, protectorKeys)
	if err != nil {
		t.Fatal("Can't make protected object")
	}
	if p_obj_2 == nil {
		t.Fatal("Bad protected object")
	}
	PrintProtectedObject(p_obj_2)

	_ = AddProtectedObject(protected_obj_list, *p_obj_1)
	_ = AddProtectedObject(protected_obj_list, *p_obj_2)

	fmt.Printf("\n\nProtected Object list:\n")
	for e := protected_obj_list.Front(); e != nil; e = e.Next() {
		o := e.Value.(ProtectedObjectMessage)
		PrintProtectedObject(&o)
	}
	fmt.Printf("\n\n")

	statuses := []string{"active"}

	seen_list := list.New()
	chain, err := ConstructProtectorChain(obj_list,
		"/jlm/file/file1", 1, nil, nil, statuses, nil, seen_list, protected_obj_list)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("Can't ConstructProtectorChain ")
	}
	fmt.Printf("Protector Chain:\n")
	for e := chain.Front(); e != nil; e = e.Next() {
		o := e.Value.(ObjectMessage)
		PrintObject(&o)
	}

	base_list := list.New()
	target := new(ObjectIdMessage)
	if target == nil {
		t.Fatal("Can't make ObjectId --- ConstructProtectorChainFromBase")
	}

	base_name := "/jlm/key/key2"
	base_epoch := int32(1)
	seen_list_base := list.New()
	target.ObjName = &base_name
	target.ObjEpoch = &base_epoch
	AddObjectId(base_list, *target)

	chain, err = ConstructProtectorChainFromBase(obj_list,
		"/jlm/file/file1", 1, statuses, nil, base_list, seen_list_base, protected_obj_list)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("Can't ConstructProtectorChainFromBase")
	}
	fmt.Printf("\nBase chain:\n")
	for e := chain.Front(); e != nil; e = e.Next() {
		o := e.Value.(ObjectMessage)
		PrintObject(&o)
	}

	base_name = "/jlm/key/key4"
	base_epoch = int32(1)
	seen_list_base = list.New()
	target.ObjName = &base_name
	target.ObjEpoch = &base_epoch
	AddObjectId(base_list, *target)
	chain, err = ConstructProtectorChainFromBase(obj_list,
		"/jlm/file/file1", 1, statuses, nil, base_list, seen_list_base, protected_obj_list)
	if err == nil {
		fmt.Printf("shouldn't have found any satisfying objects")
	}
}
