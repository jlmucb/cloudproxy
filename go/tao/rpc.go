// Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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

// This provides client stubs for the Tao interface. This code is (mostly)
// extremely dull and, ideally, would be generated automatically.

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net/rpc"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/util/protorpc"
)

// RPC sends requests between this hosted program and the host Tao.
type RPC struct {
	rpc         *rpc.Client
	serviceName string
}

// DeserializeRPC produces a RPC from a string.
func DeserializeRPC(s string) (*RPC, error) {
	if s == "" {
		return nil, newError("taorpc: missing host Tao spec" +
			" (ensure $" + HostSpecEnvVar + " is set)")
	}
	r := strings.TrimPrefix(s, "tao::RPC+")
	if r == s {
		return nil, newError("taorpc: unrecognized $" + HostSpecEnvVar + " string " + s)
	}
	ms, err := util.DeserializeFDMessageStream(r)
	if err != nil {
		return nil, newError("taorpc: unrecognized $" + HostSpecEnvVar + " string " + s +
			" (" + err.Error() + ")")
	}
	return &RPC{protorpc.NewClient(ms), "Tao"}, nil
}

// DeserializeFileRPC produces a RPC from a string representing a file.
func DeserializeFileRPC(s string) (*RPC, error) {
	if s == "" {
		return nil, newError("taorpc: missing host Tao spec" +
			" (ensure $" + HostSpecEnvVar + " is set)")
	}
	r := strings.TrimPrefix(s, "tao::RPC+")
	if r == s {
		return nil, newError("taorpc: unrecognized $" + HostSpecEnvVar + " string " + s)
	}
	ms, err := util.DeserializeFileMessageStream(r)
	if err != nil {
		return nil, newError("taorpc: unrecognized $" + HostSpecEnvVar + " string " + s +
			" (" + err.Error() + ")")
	}
	return &RPC{protorpc.NewClient(ms), "Tao"}, nil
}

// DeserializeUnixSocketRPC produces a RPC from a path string.
func DeserializeUnixSocketRPC(p string) (*RPC, error) {
	if p == "" {
		return nil, newError("taorpc: missing host Tao spec" +
			" (ensure $" + HostSpecEnvVar + " is set)")
	}

	ms, err := util.DeserializeUnixSocketMessageStream(p)
	if err != nil {
		return nil, err
	}

	return &RPC{protorpc.NewClient(ms), "Tao"}, nil
}

// NewRPC constructs a RPC for the default gob encoding rpc client using
// an io.ReadWriteCloser.
func NewRPC(rwc io.ReadWriteCloser, serviceName string) (*RPC, error) {
	return &RPC{rpc.NewClient(rwc), serviceName}, nil
}

type expectedResponse int

const (
	wantNothing expectedResponse = 0
	wantData    expectedResponse = 1 << iota
	wantPolicy
	wantLabel
	wantCounter
)

// An ErrMalformedResponse is returned as an error for an invalid response.
var ErrMalformedResponse = errors.New("taorpc: malformed response")

// call issues an rpc request, obtains the response, checks the response for
// errors, and checks that the response contains exactly the expected values.
func (t *RPC) call(method string, r *RPCRequest, e expectedResponse) (data []byte, policy string,
		counter int64, err error) {
	s := new(RPCResponse)
	err = t.rpc.Call(method, r, s)
	if err != nil {
		return
	}
	if (s.Data != nil) != (e&wantData != 0) ||
		(s.Policy != nil) != (e&wantPolicy != 0) {
		err = ErrMalformedResponse
		return
	}
	if s.Data != nil {
		data = s.Data
	}
	if s.Policy != nil {
		policy = *s.Policy
	}
	if s.Counter!= nil {
		counter = *s.Counter
	}
	return
}

// GetTaoName implements part of the Tao interface.
func (t *RPC) GetTaoName() (auth.Prin, error) {
	r := &RPCRequest{}
	data, _, _, err := t.call(t.serviceName+".GetTaoName", r, wantData)
	if err != nil {
		return auth.Prin{}, err
	}
	return auth.UnmarshalPrin(data)
}

// ExtendTaoName implements part of the Tao interface.
func (t *RPC) ExtendTaoName(subprin auth.SubPrin) error {
	r := &RPCRequest{Data: auth.Marshal(subprin)}
	_, _, _, err := t.call(t.serviceName+".ExtendTaoName", r, wantNothing)
	return err
}

type taoRandReader RPC

// Read implements part of the Tao interface.
func (t *taoRandReader) Read(p []byte) (n int, err error) {
	bytes, err := (*RPC)(t).GetRandomBytes(len(p))
	if err != nil {
		return 0, err
	}
	copy(p, bytes)
	return len(p), nil
}

// TODO(kwalsh) Can Rand be made generic, or does it need to be defined for the
// concrete type RPC?

// Rand implements part of the Tao interface.
func (t *RPC) Rand() io.Reader {
	return (*taoRandReader)(t)
}

// GetRandomBytes implements part of the Tao interface.
func (t *RPC) GetRandomBytes(n int) ([]byte, error) {
	if n > math.MaxUint32 {
		return nil, newError("taorpc: request for too many random bytes")
	}
	r := &RPCRequest{Size: proto.Int32(int32(n))}
	bytes, _, _, err := t.call(t.serviceName+".GetRandomBytes", r, wantData)
	return bytes, err
}

// GetSharedSecret implements part of the Tao interface.
func (t *RPC) GetSharedSecret(n int, policy string) ([]byte, error) {
	if n > math.MaxUint32 {
		return nil, newError("taorpc: request for too many secret bytes")
	}
	r := &RPCRequest{Size: proto.Int32(int32(n)), Policy: proto.String(policy)}
	bytes, _, _, err := t.call(t.serviceName+".GetSharedSecret", r, wantData)
	return bytes, err
}

// Attest implements part of the Tao interface.
func (t *RPC) Attest(issuer *auth.Prin, time, expiration *int64, message auth.Form) (*Attestation, error) {
	var issuerBytes []byte
	if issuer != nil {
		issuerBytes = auth.Marshal(*issuer)
	}
	r := &RPCRequest{
		Issuer:     issuerBytes,
		Time:       time,
		Expiration: expiration,
		Data:       auth.Marshal(message),
	}
	bytes, _, _, err := t.call(t.serviceName+".Attest", r, wantData)
	if err != nil {
		return nil, err
	}
	var a Attestation
	err = proto.Unmarshal(bytes, &a)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// Seal implements part of the Tao interface.
func (t *RPC) Seal(data []byte, policy string) (sealed []byte, err error) {
	r := &RPCRequest{Data: data, Policy: proto.String(policy)}
	sealed, _, _, err = t.call(t.serviceName+".Seal", r, wantData)
	return
}

// Unseal implements part of the Tao interface.
func (t *RPC) Unseal(sealed []byte) (data []byte, policy string, err error) {
	r := &RPCRequest{Data: sealed}
	data, policy, _, err = t.call(t.serviceName+".Unseal", r, wantData|wantPolicy)
	return
}

func (t *RPC) InitCounter(label string, c int64) (err error) {
	r := &RPCRequest{Label: &label, Counter: &c}
	_, _, _, err = t.call(t.serviceName+".InitCounter", r, wantNothing)
	return
}

func (t *RPC) GetCounter(label string) (c int64, err error) {
	r := &RPCRequest{Label: &label}
	fmt.Printf("RPC.GetCounter\n")
	_, _, c, err = t.call(t.serviceName+".GetCounter", r, wantCounter)
	return
}

func (t *RPC) RollbackProtectedSeal(label string, data []byte, policy string) (sealed []byte, err error) {
	fmt.Printf("RPC.RollbackProtectedSeal\n")
	return
}

func (t *RPC) RollbackProtectedUnseal(sealed []byte) (data []byte, policy string, err error) {
	fmt.Printf("RPC.RollbackProtectedUnseal\n")
	return
}

