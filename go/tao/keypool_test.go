//  Copyright (c) 2016, Google Inc.  All rights reserved.
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
	"crypto/rand"
	"testing"
)

func TestSensitiveSlice(t *testing.T) {
	length := 32
	b, err := makeSensitive(length)
	if err != nil {
		t.Fatal(err)
	} else if len(b) != length {
		t.Fatal("Didn't allocate the right number of bytes")
	}

	n, err := rand.Read(b)
	if err != nil {
		t.Fatal(err)
	} else if n != length {
		t.Fatal("Didn't read the right number of bytes")
	}

	err = clearSensitive(b)
	if err != nil {
		t.Fatal(err)
	}
}
