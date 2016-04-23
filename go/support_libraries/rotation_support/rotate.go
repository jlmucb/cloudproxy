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

// Revoke indicated object
func RevokeObject(name_obj string, epoch int) (error) {
	// FindObject(l *list.List, name string, epoch int32, types []string, statuses []string) (*ObjectMessage)
	return nil
}

// Retire indicated object
func RetireObject(name_obj string, epoch int) (error) {
	return nil
}

// Activate indicated object
func ActivateObject(name_obj string, epoch int) (error) {
	return errors.New("Not implemented") 
}

// Inactivate indicated object
func InactivateObject(name_obj string, epoch int) (error) {
	return nil
}

// Make object with new epoch and return it
func AddNewKeyEpoch(name_obj string, obj_type string, obj_status string, notBefore string, notAfter string,
                    value []byte) (*protected_objects.ObjectMessage, error) {
	// func GetLatestEpoch(l *list.List, name string, status []string) (*ObjectMessage
	// CreateObject(name string, epoch int32, obj_type *string, status *string, notBefore *time.Time,
        //      notAfter *time.Time, v []byte) (*ObjectMessage, error
	// AddObject(l *list.List, obj ObjectMessage)
	return nil, nil
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


