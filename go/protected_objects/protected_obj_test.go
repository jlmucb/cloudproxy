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
	"testing"
	"time"

	"github.com/jlmucb/cloudproxy/go/protected_objects"
	// "github.com/jlmucb/cloudproxy/go/tpm2"
	// "github.com/golang/protobuf/proto"
)

func TestStoreObject(t *testing.T) {
	// make it
	obj_type := "file"
	status := "active"
	notBefore := time.Now()
	validFor := 365*24*time.Hour
	notAfter := notBefore.Add(validFor)

	obj, err := protected_objects.CreateObject("/jlm/file/file1", 1, &obj_type, &status, &notBefore, &notAfter, nil)
	if err != nil {
		t.Fatal("Can't create object")
	}
	fmt.Printf("Obj: %s\n", *obj.NotBefore)

	// store it
	// Look it up
	// get latest epoch
	// get all epochs
}

func ConstructChain(t *testing.T) {
	// base object
	// ancestors
	// construct chain with latest epoch
	// validate chain
}




