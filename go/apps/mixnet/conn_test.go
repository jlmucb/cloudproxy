// Copyright (c) 2015, Google Inc. All rights reserved.
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
// limitations under the License0.

package mixnet

import "testing"

func stringsCompare(strs1, strs2 []string) bool {
	if len(strs1) != len(strs2) {
		return false
	}
	for i := range strs1 {
		if strs1[i] != strs2[i] {
			return false
		}
	}
	return true
}

func TestMarshalDirective(t *testing.T) {
	id := uint64(7654321)

	d := &Directive{
		Type:             DirectiveType_CREATE.Enum(),
		Addrs:            []string{"192,168.1.1:2002", "192,168.1.2:9001", "192,168.1.3:8002"},
		Error:            nil,
		XXX_unrecognized: nil,
	}

	dBytes, err := marshalDirective(id, d)
	if err != nil {
		t.Error(err)
	}

	res := new(Directive)
	var resId uint64
	err = unmarshalDirective(dBytes, &resId, res)
	if err != nil {
		t.Error(err)
	}

	if id != resId || *d.Type != *res.Type ||
		!stringsCompare(d.Addrs, res.Addrs) || d.Error != res.Error {
		t.Error("Marshalling failed")
	}
}
