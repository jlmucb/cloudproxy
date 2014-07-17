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
	"math/rand"
	"testing"
	"time"

	"code.google.com/p/goprotobuf/proto"
)

func TestInMemoryInit(t *testing.T) {
	st := new(SoftTao)
	if err := st.Init("test", "", nil); err != nil {
		t.Error(err.Error())
	}
}

func TestSoftTaoRandom(t *testing.T) {
	st := new(SoftTao)
	if err := st.Init("test", "", nil); err != nil {
		t.Error(err.Error())
	}


	if _, err := st.GetRandomBytes(10); err != nil {
		t.Error(err.Error())
	}
}

func TestSoftTaoSeal(t *testing.T) {
	st := new(SoftTao)
	if err := st.Init("test", "", nil); err != nil {
		t.Error(err.Error())
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 33)
	for i := range b {
		b[i] = byte(r.Intn(256))
	}

	_, err := st.Seal(b, SealPolicyDefault)
	if err != nil {
		t.Error(err.Error())
	}
}

func TestSoftTaoUnseal(t *testing.T) {
	st := new(SoftTao)
	if err := st.Init("test", "", nil); err != nil {
		t.Error(err.Error())
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 33)
	for i := range b {
		b[i] = byte(r.Intn(256))
	}

	s, err := st.Seal(b, SealPolicyDefault)
	if err != nil {
		t.Error(err.Error())
	}

	u, p, err := st.Unseal(s)
	if string(p) != SealPolicyDefault {
		t.Error("Invalid policy returned by Unseal")
	}

	if len(u) != len(b) {
		t.Error("Invalid unsealed length")
	}

	for i, v := range u {
		if v != b[i] {
			t.Errorf("Incorrect byte at position %d", i)
		}
	}
}

func TestSoftTaoAttest(t *testing.T) {
	st := new(SoftTao)
	if err := st.Init("test", "", nil); err != nil {
		t.Error(err.Error())
	}

	stmt := &Statement{
		Delegate: proto.String("Test Principal"),
	}

	_, err := st.Attest(stmt)
	if err != nil {
		t.Error(err.Error())
	}
}
