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
	"fmt"
	"container/list"
	"testing"
	"time"

	"github.com/jlmucb/cloudproxy/go/support_libraries/protected_objects"
	// "github.com/jlmucb/cloudproxy/go/tpm2"
	// "github.com/golang/protobuf/proto"
)

func TestBasicObject(t *testing.T) {

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
	if *obj_1.ObjId.ObjName != *p_obj_2.ObjId.ObjName {
		t.Fatal("objects don't match")
	}

	err = protected_objects.SaveObjects(obj_list, "tmptest/s1")
	if err != nil {
		t.Fatal("Can't save objects")
	}
	r := protected_objects.LoadObjects("tmptest/s1")
	if r == nil {
		t.Fatal("Can't Load objects")
	}
	e := r.Front()
	o2 := e.Value.(protected_objects.ObjectMessage)
	fmt.Printf("Recovered object\n")
	protected_objects.PrintObject(&o2)

	n1 := protected_objects.MakeNode("/jlm/key/key1", 1, "/jlm/file/file1", 1);
	if n1 == nil {
		t.Fatal("Can't make node")
	}

	n2 := protected_objects.MakeNode("/jlm/key/key2", 1, "/jlm/key/key1", 1);
	if n2 == nil {
		t.Fatal("Can't make node")
	}

	n_list := list.New()
	err = protected_objects.AddNode(n_list, *n1)
	if n1 == nil {
		t.Fatal("Can't add node")
	}
	err = protected_objects.AddNode(n_list, *n2)
	if n2 == nil {
		t.Fatal("Can't add node")
	}

	pr_list1 := protected_objects.FindProtectorNodes(n_list, "/jlm/key/key1", 1)
	if pr_list1 == nil {
		t.Fatal("FindProtectorNodes fails")
	}
	fmt.Printf("Protecting:\n")
	for e := pr_list1.Front(); e != nil; e = e.Next() {
		o := e.Value.(protected_objects.NodeMessage)
		protected_objects.PrintNode(&o)
	}
	fmt.Printf("\n")
	fmt.Printf("Protected:\n")
	pr_list2 := protected_objects.FindProtectedNodes(n_list, "/jlm/key/key1", 1)
	if pr_list2 == nil {
		t.Fatal("FindProtectedNodes fails")
	}
	for e := pr_list2.Front(); e != nil; e = e.Next() {
		o := e.Value.(protected_objects.NodeMessage)
		protected_objects.PrintNode(&o)
	}
	fmt.Printf("\n")

	statuses := []string{"active"}

	seen_list := list.New()
	chain, err := protected_objects.ConstructProtectorChain(obj_list,
		"/jlm/file/file1", 1, statuses, nil, nil, nil, seen_list, n_list)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("Can't ConstructProtectorChain ")
	}
	fmt.Printf("Protector Chain:\n")
	for e := chain.Front(); e != nil; e = e.Next() {
		o := e.Value.(protected_objects.ObjectMessage)
		protected_objects.PrintObject(&o)
	}

	base_list := list.New()
	target := new(protected_objects.ObjectIdMessage)
	if target == nil {
		t.Fatal("Can't make ObjectId --- ConstructProtectorChainFromBase")
	}

	base_name := "/jlm/key/key2"	
	base_epoch := int32(1)
	seen_list_base := list.New()
	target.ObjName = &base_name
	target.ObjEpoch= &base_epoch
	protected_objects.AddObjectId(base_list, *target)
	chain, err = protected_objects.ConstructProtectorChainFromBase(obj_list,
		"/jlm/file/file1", 1, statuses, nil, base_list, seen_list_base, n_list)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("Can't ConstructProtectorChainFromBase")
	}
	fmt.Printf("\nBase chain:\n")
	for e := chain.Front(); e != nil; e = e.Next() {
		o := e.Value.(protected_objects.ObjectMessage)
		protected_objects.PrintObject(&o)
	}

	base_name = "/jlm/key/key4"	
	base_epoch = int32(1)
	seen_list_base = list.New()
	target.ObjName = &base_name
	target.ObjEpoch= &base_epoch
	protected_objects.AddObjectId(base_list, *target)
	chain, err = protected_objects.ConstructProtectorChainFromBase(obj_list,
		"/jlm/file/file1", 1, statuses, nil, base_list, seen_list_base, n_list)
	if err == nil {
		fmt.Printf("shouldn't have found any satisfying objects")
	}
}

func TestEarliestandLatest(t *testing.T) {

	// Add three objects: a file and two keys
	obj_type := "key"
	status := "active"
	notBefore := time.Now()
	validFor := 365*24*time.Hour
	notAfter := notBefore.Add(validFor)

	obj_1, _:= protected_objects.CreateObject("/jlm/key/key1", 1,
		&obj_type, &status, &notBefore, &notAfter, nil)
	obj_2, _:= protected_objects.CreateObject("/jlm/key/key1", 2,
		&obj_type, &status, &notBefore, &notAfter, nil)

	// add them to object list
	obj_list := list.New()
	err := protected_objects.AddObject(obj_list, *obj_1)
	if err != nil {
		t.Fatal("Can't add object")
	}
	_ = protected_objects.AddObject(obj_list, *obj_2)

	statuses := []string{"active"}
	result := protected_objects.GetEarliestEpoch(obj_list, "/jlm/key/key1", statuses)
	if result == nil {
		t.Fatal("Can't get earliest epoch")
	}
	if *result.ObjId.ObjName != "/jlm/key/key1" ||
	   result.ObjId.ObjEpoch == nil || *result.ObjId.ObjEpoch != 1 {
		t.Fatal("Earliest epoch failed")
	}

	result = protected_objects.GetLatestEpoch(obj_list, "/jlm/key/key1", statuses)
	if result == nil {
		t.Fatal("Can't get latest epoch")
	}
	if *result.ObjId.ObjName != "/jlm/key/key1" ||
	   result.ObjId.ObjEpoch == nil || *result.ObjId.ObjEpoch != 2 {
		protected_objects.PrintObject(result)
		t.Fatal("Latest epoch failed")
	}
}

func TestSaveAndRestore(t *testing.T) {
}

func TestConstructChain(t *testing.T) {
	// base object
	// ancestors
	// construct chain with latest epoch
	// validate chain
}


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
