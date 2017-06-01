// Copyright (c) 2016, Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package secret_service

import (
	"bytes"
	"container/list"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/jlmucb/cloudproxy/go/support_libraries/protected_objects"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

var epoch = int32(1)

var rootName = "RootName"
var rootKey []byte
var rootId *protected_objects.ObjectIdMessage

var name = "KeyName"
var secretType = "key"
var value = []byte("I am a key.")

var domain *tao.Domain
var encKey *tao.Keys

var authorizedPrin = &auth.Prin{
	Type:    "program",
	KeyHash: auth.Bytes([]byte("Hash-of-AuthorizedProgram-Key")),
	Ext:     []auth.PrinExt{}}

var unAuthorizedPrin = &auth.Prin{
	Type:    "program",
	KeyHash: auth.Bytes([]byte("Hash-of-UnAuthorizedProgram-Key")),
	Ext:     []auth.PrinExt{}}

func TestReadObject(t *testing.T) {
	setUpDomain(t)
	l := list.New()
	l.PushFront(createRootKey(t))
	obj := createObject(name, epoch, value, secretType)
	pObj, err := protected_objects.MakeProtectedObject(*obj, rootName, epoch, rootKey)
	failOnError(t, err)
	l.PushFront(*pObj)

	err = domain.Guard.Authorize(*authorizedPrin, "READ", []string{obj.ObjId.String()})
	failOnError(t, err)

	typ, val, err := ReadObject(l, encKey, obj.ObjId, authorizedPrin, domain)
	failOnError(t, err)
	if *typ != secretType {
		t.Fatal("Object type read does not match expected type.")
	}
	if !bytes.Equal(val, value) {
		t.Fatal("Object value read does not match expected value.")
	}

	_, _, err = ReadObject(l, encKey, createObjectId("Not there", int32(0)),
		authorizedPrin, domain)
	if err == nil {
		t.Fatal("Reading for a missing object returned nil error.")
	}

	_, _, err = ReadObject(list.New(), encKey, obj.ObjId, authorizedPrin, domain)
	if err == nil {
		t.Fatal("Reading an empty list returned nil error.")
	}

	_, _, err = ReadObject(l, encKey, obj.ObjId, unAuthorizedPrin, domain)
	if err == nil {
		t.Fatal("Reading by an unauthorized principal returned nil error.")
	}
	tearDown(t)
}

func TestWriteObject(t *testing.T) {
	setUpDomain(t)
	l := list.New()
	l.PushFront(createRootKey(t))
	obj := createObject(name, epoch, value, secretType)
	pObj, err := protected_objects.MakeProtectedObject(*obj, rootName, epoch, rootKey)
	failOnError(t, err)
	l.PushFront(*pObj)

	err = domain.Guard.Authorize(*authorizedPrin, "WRITE", []string{obj.ObjId.String()})
	failOnError(t, err)
	err = domain.Guard.Authorize(*authorizedPrin, "READ", []string{obj.ObjId.String()})
	failOnError(t, err)

	newType := "file"
	newVal := []byte("I am a new file")
	err = WriteObject(l, encKey, obj.ObjId, authorizedPrin, domain, newType, newVal)
	failOnError(t, err)
	typ, val, err := ReadObject(l, encKey, obj.ObjId, authorizedPrin, domain)
	failOnError(t, err)
	if *typ != newType {
		t.Fatal(fmt.Sprintf("Expected secret type %v got %v", newType, typ))
	}
	if !bytes.Equal(val, newVal) {
		t.Fatal("value read after write does not match expected value.")
	}
	tearDown(t)
}

func TestCreateObject(t *testing.T) {
	setUpDomain(t)
	l := list.New()
	l.PushFront(createRootKey(t))

	err := domain.Guard.Authorize(*authorizedPrin, "CREATE", []string{rootId.String()})
	failOnError(t, err)
	id := createObjectId(name, epoch)
	err = domain.Guard.Authorize(*authorizedPrin, "READ", []string{id.String()})
	failOnError(t, err)
	fileType := "file"
	err = CreateObject(l, id, rootId, encKey, authorizedPrin, domain, fileType, value)
	failOnError(t, err)
	typ, val, err := ReadObject(l, encKey, id, authorizedPrin, domain)
	failOnError(t, err)
	if *typ != fileType {
		t.Fatal(fmt.Sprintf("Expected secret type %v got %v", secretType, typ))
	}
	if !bytes.Equal(val, value) {
		t.Fatal("value read after create does not match expected value.")
	}

	err = CreateObject(l, id, rootId, encKey, authorizedPrin, domain, secretType, value)
	if err == nil {
		t.Fatal("Did not get error by creating new object with existing id.")
	}

	newId := createObjectId("NewKey", epoch)
	newValue := []byte("A New Value!")
	err = CreateObject(l, newId, id, encKey, authorizedPrin, domain, secretType, newValue)
	if err == nil {
		t.Fatal("Did not get error by creating new object with unauthorized program.")
	}

	err = domain.Guard.Authorize(*authorizedPrin, "CREATE", []string{id.String()})
	failOnError(t, err)
	err = CreateObject(l, newId, newId, encKey, authorizedPrin, domain, secretType, newValue)
	if err == nil {
		t.Fatal("Did not get error by creating new object with a non existant protectorId.")
	}

	err = CreateObject(l, newId, id, encKey, authorizedPrin, domain, secretType, newValue)
	if err == nil {
		t.Fatal("Did not get error by creating new object with non-key protector.")
	}
	tearDown(t)
}

func TestDeleteObject(t *testing.T) {
	setUpDomain(t)
	l := list.New()
	l.PushFront(createRootKey(t))

	newId := createObjectId(name, epoch)
	err := DeleteObject(l, newId, authorizedPrin, domain)
	if err == nil {
		t.Fatal("Did not get error when unauthorized program attempted to delete object.")
	}

	err = domain.Guard.Authorize(*authorizedPrin, "DELETE", []string{newId.String()})
	failOnError(t, err)
	err = DeleteObject(l, newId, authorizedPrin, domain)
	if err == nil {
		t.Fatal("Did not get error when program attempts to delete non-existant object.")
	}

	err = domain.Guard.Authorize(*authorizedPrin, "CREATE", []string{rootId.String()})
	failOnError(t, err)
	err = CreateObject(l, newId, rootId, encKey, authorizedPrin, domain, secretType, value)
	failOnError(t, err)
	err = DeleteObject(l, newId, authorizedPrin, domain)
	failOnError(t, err)
	err = domain.Guard.Authorize(*authorizedPrin, "READ", []string{newId.String()})
	failOnError(t, err)
	_, _, err = ReadObject(l, encKey, newId, authorizedPrin, domain)
	if err == nil {
		t.Fatal("Reading a previously deleted object did not return error.")
	}
	tearDown(t)
}

func failOnError(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func createObject(name string, epoch int32, value []byte,
	objType string) *protected_objects.ObjectMessage {
	return &protected_objects.ObjectMessage{
		ObjId:   createObjectId(name, epoch),
		ObjVal:  value,
		ObjType: &objType}
}

func createObjectId(name string, epoch int32) *protected_objects.ObjectIdMessage {
	return &protected_objects.ObjectIdMessage{
		ObjName:  &name,
		ObjEpoch: &epoch}
}

func createRootKey(t *testing.T) protected_objects.ProtectedObjectMessage {
	rootKey = make([]byte, 32)
	_, err := rand.Read(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	p := new(protected_objects.ProtectedObjectMessage)
	rootId = createObjectId(rootName, epoch)
	p.ProtectedObjId = rootId
	encrypted, err := encKey.CryptingKey.Encrypt(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	p.Blob = encrypted
	return *p
}

func setUpDomain(t *testing.T) {
	var err error
	if _, err = os.Stat("./tmpdir"); os.IsNotExist(err) {
		err = os.Mkdir("./tmpdir", 0777)
		if err != nil {
			t.Fatal(err)
		}
	}
	aclGuardType := "ACLs"
	aclGuardPath := "acls"
	cfg := tao.DomainConfig{
		DomainInfo: &tao.DomainDetails{
			GuardType: &aclGuardType},
		AclGuardInfo: &tao.ACLGuardDetails{
			SignedAclsPath: &aclGuardPath}}
	domain, err = tao.CreateDomain(cfg, "./tmpdir/domain", []byte("xxx"))
	if err != nil {
		t.Fatal(err)
	}
	encKey, err = tao.NewOnDiskPBEKeys(tao.Crypting, []byte("xxx"), "./tmpdir/keys", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func tearDown(t *testing.T) {
	err := os.RemoveAll("./tmpdir")
	if err != nil {
		t.Fatal(err)
	}
}
