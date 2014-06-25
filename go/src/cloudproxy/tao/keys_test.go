//  Copyright (c) 2014, Google Inc.  All rights reserved.
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

package tao

import (
	"testing"
)

func TestTempKeys(t *testing.T) {
	msg := []byte("test msg")
	ctxt := []byte("test context")
	k := NewTempKeys("test", Signing | Crypting | KeyDeriving)
	sig, err := k.Sign(msg, ctxt)
	if err != nil {
		t.Error(err.Error())
	}

	if b, err := k.Verify(msg, ctxt, []byte(sig)); (!b || err != nil) {
		t.Error("The message didn't pass verification")
	}
}
