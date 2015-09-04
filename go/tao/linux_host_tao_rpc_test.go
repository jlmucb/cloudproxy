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

// This now tests a full round trip:
// RPC -> protorpc -> pipe -> protorpc -> LinuxHostTaoServer -> LinuxHost
// RPC <- protorpc <- pipe <- protorpc <- LinuxHostTaoServer <- LinuxHost

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/util/protorpc"
)

type DummyChild struct {
	channel io.ReadWriteCloser
	subprin auth.SubPrin
}

func (d *DummyChild) Spec() HostedProgramSpec {
	return HostedProgramSpec{}
}

func (d *DummyChild) Subprin() auth.SubPrin {
	return d.subprin
}

func (d *DummyChild) Extend(ext auth.SubPrin) {
	d.subprin = append(d.subprin, ext...)
}
func (d *DummyChild) Start() error {
	return nil
}
func (d *DummyChild) Kill() error {
	return nil
}
func (d *DummyChild) Stop() error {
	return nil
}
func (d *DummyChild) Channel() io.ReadWriteCloser {
	return d.channel
}
func (d *DummyChild) WaitChan() <-chan bool {
	return nil
}
func (d *DummyChild) Cleanup() error {
	return nil
}
func (d *DummyChild) Pid() int {
	return 0
}
func (d *DummyChild) ExitStatus() (int, error) {
	return 0, nil
}

func testNewLinuxHostTaoServer(t *testing.T) (Tao, error) {
	lh, err := testNewRootLinuxHost()
	if err != nil {
		return nil, fmt.Errorf("Can't make root linux host: %s", err)
	}

	hostRead, childWrite, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("Can't make pipe: %s", err)
	}

	childRead, hostWrite, err := os.Pipe()
	if err != nil {
		childWrite.Close()
		hostRead.Close()
		return nil, fmt.Errorf("Can't make pipe: %s", err)
	}

	hostChannel := util.NewPairReadWriteCloser(hostRead, hostWrite)
	childChannel := util.NewPairReadWriteCloser(childRead, childWrite)

	child := &DummyChild{
		channel: hostChannel,
		subprin: []auth.PrinExt{auth.PrinExt{Name: "TestChild"}},
	}

	go NewLinuxHostTaoServer(lh, child).Serve(hostChannel)
	return &RPC{protorpc.NewClient(childChannel), "Tao"}, nil
}

func TestLinuxHostTaoServerGetTaoName(t *testing.T) {
	host, err := testNewLinuxHostTaoServer(t)
	if err != nil {
		t.Fatal(err)
	}
	prin, err := host.GetTaoName()
	if err != nil {
		t.Fatal("Couldn't get the Tao name from the LinuxHostTaoServer:", err)
	}
	if prin.String() == "" {
		t.Fatal("Got bad Tao name from the LinuxHostTaoServer:", prin.String())
	}
}

func TestLinuxHostTaoServerExtendTaoName(t *testing.T) {
	host, err := testNewLinuxHostTaoServer(t)
	if err != nil {
		t.Fatal(err)
	}
	ext := auth.SubPrin{auth.PrinExt{Name: "Extension"}}
	if err := host.ExtendTaoName(ext); err != nil {
		t.Fatal("Couldn't extend the Tao name through LinuxHostTaoServer:", err)
	}
}

func TestLinuxHostTaoServerGetRandomBytes(t *testing.T) {
	host, err := testNewLinuxHostTaoServer(t)
	if err != nil {
		t.Fatal(err)
	}
	data, err := host.GetRandomBytes(10)
	if err != nil {
		t.Fatal("Couldn't get random bytes from LinuxHostTaoServer:", err)
	}
	if len(data) != 10 {
		t.Fatal("Wrong number of bytes returned from GetRandomBytes on LinuxHostTaoServer. Expected 10 and got " + strconv.Itoa(len(data)))
	}
}

func TestLinuxHostTaoServerSealUnseal(t *testing.T) {
	host, err := testNewLinuxHostTaoServer(t)
	if err != nil {
		t.Fatal(err)
	}
	orig := []byte{1, 2, 3, 4, 5}
	sealed, err := host.Seal(orig, SealPolicyDefault)
	if err != nil {
		t.Fatal("Couldn't seal the data using LinuxHostTaoServer:", err)
	}
	if len(sealed) == 0 {
		t.Fatal("Invalid sealed data from LinuxHostTaoServer")
	}
	unsealed, policy, err := host.Unseal(sealed)
	if err != nil {
		t.Fatal("Couldn't unseal data sealed by LinuxHostTaoServer:", err)
	}
	if !bytes.Equal(unsealed, orig) {
		t.Fatal("Incorrect data unsealed by Seal/Unseal on LinuxHostTaoServer")
	}
	if policy != SealPolicyDefault {
		t.Fatal("Incorrect policy on unseal")
	}
}

func TestLinuxHostTaoServerAttest(t *testing.T) {
	host, err := testNewLinuxHostTaoServer(t)
	if err != nil {
		t.Fatal(err)
	}
	prin, err := host.GetTaoName()
	if err != nil {
		t.Fatal("Couldn't get the Tao name from the LinuxHostTaoServer:", err)
	}

	issuer := prin
	commencement := time.Now().UnixNano()
	expiration := time.Now().Add(24 * time.Hour).UnixNano()
	message := auth.Pred{Name: "FakePredicate"}

	a, err := host.Attest(&issuer, &commencement, &expiration, message)
	if err != nil {
		t.Fatal("Couldn't attest to data through LinuxHostTaoServer:", err)
	}
	if a == nil {
		t.Fatal("Invalid Attestation returned by LinuxHostTaoServer")
	}
	// TODO(tmroeder): verify the attestation

	a, err = host.Attest(nil, &commencement, &expiration, message)
	if err != nil {
		t.Fatal("Couldn't attest to data through LinuxHostTaoServer:", err)
	}
	if a == nil {
		t.Fatal("Invalid Attestation returned by LinuxHostTaoServer")
	}
	// TODO(tmroeder): verify the attestation

	a, err = host.Attest(nil, nil, nil, message)
	if err != nil {
		t.Fatal("Couldn't attest to data through LinuxHostTaoServer:", err)
	}
	if a == nil {
		t.Fatal("Invalid Attestation returned by LinuxHostTaoServer")
	}

	// TODO(tmroeder): verify the attestation
}
