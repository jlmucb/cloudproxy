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
	"time"

	// "github.com/golang/protobuf/proto"
)

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

