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
	"fmt"
	"time"

	"github.com/jlmucb/cloudproxy/go/support_libraries/protected_objects"
)

func ChangeObjectStatus(l *list.List, name_obj string, epoch int, new_status string) error {
	obj := protected_objects.FindObject(l, name_obj, int32(epoch), nil, nil)
	if obj == nil {
		return errors.New("Can't find object")
	}
	obj.ObjStatus = &new_status
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

func ForceInclude() {
	fmt.Printf("Include forced")
}

// Make object with new epoch and return it
func AddNewKeyEpoch(l *list.List, name_obj string, obj_type string, existing_status string, new_status string,
		    notBefore string, notAfter string,
                    value []byte) (*protected_objects.ObjectMessage, *protected_objects.ObjectMessage, error) {
	new_epoch := 1
	old_obj := protected_objects.GetLatestEpoch(l, name_obj, []string{existing_status})
	if old_obj != nil {
		new_epoch = int(*old_obj.ObjId.ObjEpoch + 1)
	}
	nb, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", notBefore)
	if err != nil {
		return nil,nil, errors.New("Can't parse notBefore")
	}
	na, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", notAfter)
	if err != nil {
		return nil,nil, errors.New("Can't parse notAfter")
	}
	new_obj, err := protected_objects.CreateObject(name_obj, int32(new_epoch), &obj_type,
			&new_status, &nb, &na, value)
	if err != nil || new_obj == nil {
		return nil,nil, errors.New("Can't create new object")
	}
	err = protected_objects.AddObject(l, *new_obj)
	if err != nil {
		return nil,nil, errors.New("Can't add new object")
	}
	return old_obj, new_obj, nil
}

// Find all the objects protected by existing object.
// For each, make a new protected object with new protector.
// Add all resulting nodes to the node list.
// Return new epoch.
func AddAndRotateNewKeyEpoch(name_obj string,  obj_type string, existing_status string,
		new_status string, notBefore string, notAfter string, value []byte,
		obj_list *list.List, protected_obj_list *list.List) (int, error) {
	old_obj, new_obj, err := AddNewKeyEpoch(obj_list, name_obj, obj_type, existing_status,
                    new_status, notBefore, notAfter, value)
	if err != nil || new_obj == nil {
		return -1, errors.New("Can't create new epoch")
	}
	err = protected_objects.AddObject(obj_list, *new_obj)
	if err != nil {
		return -1, errors.New("Can't add new key")
	}
	if old_obj == nil {
		return 1, nil
	}
	old_protected := protected_objects.FindProtectedObjects(protected_obj_list, name_obj, *old_obj.ObjId.ObjEpoch)
	if old_protected == nil  || old_protected.Len() <= 0 {
		fmt.Printf("old protector: %s, %d\n", name_obj, *old_obj.ObjId.ObjEpoch)
		return -1, errors.New("Can't Find protected nodes")
	}
	for e := old_protected.Front(); e != nil; e = e.Next() {
		old := e.Value.(protected_objects.ProtectedObjectMessage)
		protected_name := *old.ProtectedObjId.ObjName
		protected_epoch := *old.ProtectedObjId.ObjEpoch
		old_protected_obj := protected_objects.FindObject(obj_list, protected_name, protected_epoch, nil, nil)
		if old_protected_obj == nil {
		}
		new_protected_obj, err := protected_objects.MakeProtectedObject(*old_protected_obj,
					*new_obj.ObjId.ObjName, *new_obj.ObjId.ObjEpoch, new_obj.ObjVal)
		if new_protected_obj == nil || err != nil {
			return -1, errors.New("Can't make new protected object")
		}
		err = protected_objects.AddProtectedObject(protected_obj_list, *new_protected_obj)
		if err != nil {
			return -1, errors.New("Can't add new protected node")
		}
	}
	_ = RetireObject(obj_list, *old_obj.ObjId.ObjName, int(*old_obj.ObjId.ObjEpoch))
	return int(*new_obj.ObjId.ObjEpoch), nil
}
