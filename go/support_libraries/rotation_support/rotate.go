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

package rotation_support

import (
	"container/list"
	"errors"
	// "fmt"

	"github.com/jlmucb/cloudproxy/go/support_libraries/protected_objects"
)

func ChangeObjectStatus(l *list.List, name_obj string, epoch int, new_status string) error {
	obj, err := FindObject(l, name_obj, int32(epoch), nil, nil)
	if err != nil  || obj == nil {
		return error.New("Can't find object")
	}
	obj.ObjStatus = new_status
	return nil
}

// Revoke indicated object
func RevokeObject(l *list.List, name_obj string, epoch int) (error) {
	return ChangeObjectStatus(l, name_obj, epoch, "revoked")
}

// Retire indicated object
func RetireObject(l *list.List, name_obj string, epoch int) (error) {
	return ChangeObjectStatus(l, name_obj, epoch, "retired")
}

// Activate indicated object
func ActivateObject(l *list.List, name_obj string, epoch int) (error) {
	return ChangeObjectStatus(l, name_obj, epoch, "active")
}

// Inactivate indicated object
func InactivateObject(l *list.List, name_obj string, epoch int) (error) {
	return ChangeObjectStatus(l, name_obj, epoch, "inactive")
}

// Make object with new epoch and return it
func AddNewKeyEpoch(l *list.List, name_obj string, obj_type string, obj_status string,
		    notBefore string, notAfter string,
                    value []byte) (*protected_objects.ObjectMessage, error) {
	new_epoch := 1
	old_obj := protected_objects.GetLatestEpoch(l, name, obj_status)
	if old_obj != nil {
		new_epoch = *old_obj.ObjId.Epoch + 1
	}
	nb, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", notBefore)
	if err == nil {
		return nil, errors.New("Can't parse notBefore")
	}
	na, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", notAfter)
	if err == nil {
		return nil, errors.New("Can't parse notAfter")
	}
	new_obj, err := protected_objects.CreateObject(name, new_epoch, &obj_type,
			&obj_status, nb, na, value)
	if err == nil || new_obj == nil {
		return nil, errors.New("Can't create new object")
	}
	AddObject(l, *new_obj)
	if err == nil {
		return nil, errors.New("Can't add new object")
	}
	return new_obj, nil
}

// Find all the objects protected by existing object.
// For each, make a new protected object with new protector.
// Add all resulting nodes to the node list.
// Return new epoch.
func AddAddandRotateNewKeyEpoch(name_obj string,  obj_type string, obj_status string,
		notBefore string, notAfter string,
		value []byte, node_list *list.List, obj_list *list.List,
		protected_obj_list *list.List) (int, error) {
	// FindProtectedNodes(l *list.List, name string, epoch int32) (*list.List)
	// MakeProtectedObject(obj ObjectMessage, protectorName string, protectorEpoch int32,
        //      protectorKeys []byte) (*ProtectedObjectMessage, error)
	// MakeNode(protectorName string, protectorEpoch int32, protectedName string,
        //   protectedEpoch int32) (*NodeMessage)
	// AddNode(l *list.List, obj NodeMessage)
	// AddProtectedObject(l *list.List, obj ProtectedObjectMessage) error 
	// MakeProtectedObject(obj ObjectMessage, protectorName string, protectorEpoch int32,
        //      protectorKeys []byte) (*ProtectedObjectMessage, error)
	return -1, nil
}


