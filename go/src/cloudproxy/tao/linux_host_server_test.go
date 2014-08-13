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
	"bytes"
	"os"
	"strconv"
	"testing"
	"time"

	"code.google.com/p/goprotobuf/proto"

	"cloudproxy/tao/auth"
)

func testNewLinuxHostServer(t *testing.T) (*LinuxHostServer, string) {
	lh, tmpdir := testNewRootLinuxHost(t)

	// The channel and Cmd are used by admin operations in the Linux host,
	// so they don't need to be filled here.
	lhs := &LinuxHostServer{
		host:         lh,
		ChildSubprin: auth.SubPrin{auth.PrinExt{Name:"TestChild"}},
	}
	return lhs, tmpdir
}

func TestLinuxHostServerGetTaoName(t *testing.T) {
	r := &TaoRPCRequest{}
	s := &TaoRPCResponse{}
	lhs, tmpdir := testNewLinuxHostServer(t)
	defer os.RemoveAll(tmpdir)
	if err := lhs.GetTaoName(r, s); err != nil {
		t.Fatal("Couldn't get the Tao name from the LinuxHostServer:", err)
	}

	if s.Data == nil {
		t.Fatal("Couldn't get a name back from GetTaoName on LinuxHostServer")
	}
}

func TestLinuxHostServerExtendTaoName(t *testing.T) {
	r := &TaoRPCRequest{
		Data: auth.Marshal(auth.SubPrin{auth.PrinExt{Name:"Extension"}}),
	}
	s := &TaoRPCResponse{}
	lhs, tmpdir := testNewLinuxHostServer(t)
	defer os.RemoveAll(tmpdir)
	if err := lhs.ExtendTaoName(r, s); err != nil {
		t.Fatal("Couldn't extend the Tao name through LinuxHostServer:", err)
	}
}

func TestLinuxHostServerGetRandomBytes(t *testing.T) {
	r := &TaoRPCRequest{
		Size: proto.Int32(10),
	}
	s := &TaoRPCResponse{}
	lhs, tmpdir := testNewLinuxHostServer(t)
	defer os.RemoveAll(tmpdir)
	if err := lhs.GetRandomBytes(r, s); err != nil {
		t.Fatal("Couldn't get random bytes from LinuxHostServer:", err)
	}

	if len(s.Data) != 10 {
		t.Fatal("Wrong number of bytes returned from GetRandomBytes on LinuxHostServer. Expected 10 and got " + strconv.Itoa(len(s.Data)))
	}
}

func TestLinuxHostServerSealUnseal(t *testing.T) {
	// We keep a separate copy of the data, since seal clears it.
	orig := []byte{1, 2, 3, 4, 5}
	r := &TaoRPCRequest{
		Data:   []byte{1, 2, 3, 4, 5},
		Policy: proto.String(SealPolicyDefault),
	}
	s := &TaoRPCResponse{}
	lhs, tmpdir := testNewLinuxHostServer(t)
	defer os.RemoveAll(tmpdir)
	if err := lhs.Seal(r, s); err != nil {
		t.Fatal("Couldn't seal the data using LinuxHostServer")
	}

	if len(s.Data) == 0 {
		t.Fatal("Invalid sealed data from LinuxHostServer")
	}

	r2 := &TaoRPCRequest{
		Data: s.Data,
	}
	s2 := &TaoRPCResponse{}
	if err := lhs.Unseal(r2, s2); err != nil {
		t.Fatal("Couldn't unseal data sealed by LinuxHostServer")
	}

	if !bytes.Equal(s2.Data, orig) {
		t.Fatal("Incorrect data unsealed by Seal/Unseal on LinuxHostServer")
	}
}

func TestLinuxHostServerAttest(t *testing.T) {
	rt := &TaoRPCRequest{}
	st := &TaoRPCResponse{}
	lhs, tmpdir := testNewLinuxHostServer(t)
	defer os.RemoveAll(tmpdir)
	if err := lhs.GetTaoName(rt, st); err != nil {
		t.Fatal("Couldn't get the Tao name from the LinuxHostServer:", err)
	}

	message := auth.Pred{Name: "FakePredicate"}

	r := &TaoRPCRequest{
		Data:          auth.Marshal(message),
		Time:          proto.Int64(time.Now().UnixNano()),
		Expiration:    proto.Int64(time.Now().Add(24 * time.Hour).UnixNano()),
		Issuer:        st.Data,
	}
	s := &TaoRPCResponse{}
	if err := lhs.Attest(r, s); err != nil {
		t.Fatal("Couldn't attest to data through LinuxHostServer:", err)
	}

	if len(s.Data) == 0 {
		t.Fatal("Invalid marshalled Attestation data returned by LinuxHostServer")
	}

	var a Attestation
	if err := proto.Unmarshal(s.Data, &a); err != nil {
		t.Fatal("Couldn't unmarshal into an Attestation the data returned by Attest on LinuxHostServer")
	}

	// TODO(tmroeder): verify the attestation
}
