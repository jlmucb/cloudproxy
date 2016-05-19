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
	"container/list"
	"errors"

	"github.com/jlmucb/cloudproxy/go/support_libraries/protected_objects"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

func ReadObject(l *list.List, encKey *tao.Keys, id *protected_objects.ObjectIdMessage,
	program *auth.Prin, domain *tao.Domain) (*string, []byte, error) {

	if !domain.Guard.IsAuthorized(*program, "READ", []string{id.String()}) {
		return nil, nil, errors.New("program not authorized to read requested secret")
	}
	return readObjRec(l, encKey, id)
}

func readObjRec(l *list.List, encKey *tao.Keys, id *protected_objects.ObjectIdMessage) (*string,
	[]byte, error) {

	elem := protected_objects.FindElementById(l, *id.ObjName, *id.ObjEpoch)
	if elem == nil {
		return nil, nil, errors.New("object not found")
	}
	pObj := elem.Value.(protected_objects.ProtectedObjectMessage)
	if pObj.ProtectorObjId == nil {
		// Decrypt root using encKeys.
		rootKey, err := encKey.CryptingKey.Decrypt(pObj.GetBlob())
		if err != nil {
			return nil, nil, err
		}
		str := "key"
		return &str, rootKey, nil
	}
	parentType, parentKey, err := readObjRec(l, encKey, pObj.ProtectorObjId)
	if err != nil {
		return nil, nil, err
	}
	if *parentType != "key" {
		return nil, nil, errors.New("internal node with type not key")
	}
	obj, err := protected_objects.RecoverProtectedObject(&pObj, parentKey)
	if err != nil {
		return nil, nil, err
	}
	return obj.ObjType, obj.ObjVal, nil
}

func WriteObject(l *list.List, encKey *tao.Keys, id *protected_objects.ObjectIdMessage,
	program *auth.Prin, domain *tao.Domain, newType string,
	newVal []byte) error {

	if !domain.Guard.IsAuthorized(*program, "WRITE", []string{id.String()}) {
		return errors.New("program not authorized to write requested secret")
	}

	element := protected_objects.FindElementById(l, *id.ObjName, *id.ObjEpoch)
	if element == nil {
		return errors.New("attemtping to write non-existant object")
	}
	pOld := element.Value.(protected_objects.ProtectedObjectMessage)
	parentId := pOld.ProtectorObjId
	if parentId == nil {
		return errors.New("attempting to write root key")
	}
	parentType, parentKey, err := readObjRec(l, encKey, parentId)
	if err != nil {
		return err
	}
	if *parentType != "key" {
		return errors.New("parent of object to be written is not a key")
	}
	new := protected_objects.ObjectMessage{
		ObjId:   id,
		ObjVal:  newVal,
		ObjType: &newType}
	pNew, err := protected_objects.MakeProtectedObject(new, *parentId.ObjName,
		*parentId.ObjEpoch, parentKey)
	if err != nil {
		return errors.New("can not make protected object")
	}
	element.Value = *pNew
	return nil
}

func CreateObject(l *list.List, newId, protectorId *protected_objects.ObjectIdMessage,
	encKey *tao.Keys, program *auth.Prin, domain *tao.Domain, newType string,
	newVal []byte) error {

	if !domain.Guard.IsAuthorized(*program, "CREATE", []string{protectorId.String()}) {
		return errors.New("program not authorized to create requested secret")
	}

	_, _, err := readObjRec(l, encKey, newId)
	if err == nil {
		return errors.New("creating object with existing id")
	}

	protectorType, protectorKey, err := readObjRec(l, encKey, protectorId)
	if err != nil {
		return err
	}
	if *protectorType != "key" {
		return errors.New("creating object protected by object type not key")
	}

	new := protected_objects.ObjectMessage{
		ObjId:   newId,
		ObjVal:  newVal,
		ObjType: &newType}
	pNew, err := protected_objects.MakeProtectedObject(new, *protectorId.ObjName,
		*protectorId.ObjEpoch, protectorKey)

	l.PushFront(*pNew)
	return nil
}

func DeleteObject(l *list.List, id *protected_objects.ObjectIdMessage, program *auth.Prin,
	domain *tao.Domain) error {

	if !domain.Guard.IsAuthorized(*program, "DELETE", []string{id.String()}) {
		return errors.New("program not authorized to delete requested secret")
	}

	element := protected_objects.FindElementById(l, *id.ObjName, *id.ObjEpoch)
	if element == nil {
		return errors.New("object to be deleted not found")
	}
	l.Remove(element)
	return nil
}
