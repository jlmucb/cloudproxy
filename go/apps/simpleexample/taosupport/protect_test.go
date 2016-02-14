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

package taosupport

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	taosupport "github.com/jlmucb/cloudproxy/go/apps/simpleexample/taosupport"
)


func TestProtect(t *testing.T) {
	in := make([]byte, 40, 40)
	for i := 0; i < 40; i++ {
		in[i] = byte(i)
	}

	keys := make([]byte, 32, 32)
	rand.Read(keys[0:32])
	out, err := taosupport.Protect(keys, in[0:40])
	if  err != nil {
		t.Fatal("Protect fails\n")
	}

	fmt.Printf("in        : %x\n", in[0:40])
	fmt.Printf("keys      : %x\n", keys[0:32])
	fmt.Printf("out       : %x\n", out)

	out_decrypted, err := taosupport.Unprotect(keys, out)
	if  err != nil {
		t.Fatal("Unprotected fails\n")
	}
	fmt.Printf("decrypted : %x\n", out_decrypted)
	if bytes.Compare(in, out_decrypted) != 0 {
		t.Fatal("decrypted does not match in\n")
	}
	fmt.Printf("TestProtect succeeds\n")
}

