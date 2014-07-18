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
	"net/rpc"
	"testing"
	"time"

	"cloudproxy/util"
	"code.google.com/p/goprotobuf/proto"
)

func TestTaoChanServer(t *testing.T) {
	serverWrite := make(chan []byte)
	clientWrite := make(chan []byte)
	c := &util.ChanReadWriteCloser{
		R: serverWrite,
		W: clientWrite,
	}

	s := &util.ChanReadWriteCloser{
		R: clientWrite,
		W: serverWrite,
	}

	server := rpc.NewServer()
	tao := new(FakeTao)
	if err := tao.Init("test", "", nil); err != nil {
		t.Error(err.Error())
	}

	t.Log("Initialized the keys")

	ts := &TaoServer{
		T: tao,
	}

	err := server.Register(ts)
	if err != nil {
		panic(err)
	}

	go server.ServeConn(s)

	tc := &TaoClient{
		Parent: rpc.NewClient(c),
	}
	defer tc.Parent.Close()

	b, err := tc.GetRandomBytes(10)
	if err != nil {
		t.Error("Couldn't get random bytes:", err)
	}

	t.Log("Got 10 random bytes")

	// Seal, Unseal, and Attest to the bytes
	sealed, err := tc.Seal(b, SealPolicyDefault)
	if err != nil {
		t.Error("Couldn't seal the data:", err)
	}

	unsealed, policy, err := tc.Unseal(sealed)
	if err != nil {
		t.Error("Couldn't unseal the data:", err)
	}

	if string(policy) != SealPolicyDefault {
		t.Error("Invalid policy returned by the Tao")
	}

	if len(unsealed) != len(b) {
		t.Error("Invalid unsealed length")
	}

	for i, v := range unsealed {
		if v != b[i] {
			t.Errorf("Incorrect value returned at byte %d\n", i)
		}
	}

	stmt := &Statement{
		// TODO(tmroeder): Issuer, Time, and Expiration are required, but they
		// should be optional.
		Issuer:     proto.String("test"),
		Time:       proto.Int64(time.Now().UnixNano()),
		Expiration: proto.Int64(time.Now().UnixNano() + 100),
		Delegate:   proto.String(string(b)),
	}

	_, err = tc.Attest(stmt)
	if err != nil {
		t.Error("Couldn't attest to the bytes:", err)
	}

	t.Log("All actions worked correctly")
}
