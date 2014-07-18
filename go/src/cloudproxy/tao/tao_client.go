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
	"io"
	"net/rpc"

	"code.google.com/p/goprotobuf/proto"
)

// TaoClient implements the Tao and passes on calls to a parent Tao across an
// RPC channel.
type TaoClient struct {
	Parent *rpc.Client
}

// GetTaoName returns the Tao principal name assigned to the caller.
func (t *TaoClient) GetTaoName() (string, error) {
	r := &TaoRPCRequest{
		Rpc: TaoRPCOperation_TAO_RPC_GET_TAO_NAME.Enum(),
	}

	s := new(TaoRPCResponse)
	err := t.Parent.Call("TaoServer.GetRandomBytes", r, s)
	if err != nil {
		return "", err
	}

	return string(s.Data), nil
}

// ExtendTaoName irreversibly extends the Tao principal name of the caller.
func (t *TaoClient) ExtendTaoName(subprin string) error {
	r := &TaoRPCRequest{
		Rpc:  TaoRPCOperation_TAO_RPC_EXTEND_TAO_NAME.Enum(),
		Data: []byte(subprin),
	}

	s := new(TaoRPCResponse)
	err := t.Parent.Call("TaoServer.ExtendTaoName", r, s)
	if err != nil {
		return err
	}

	return nil
}

// Read reads random bytes from the remote Tao server. This implements
// io.Reader.
func (t *TaoClient) Read(p []byte) (int, error) {
	b, err := t.GetRandomBytes(len(p))
	if err != nil {
		return 0, err
	}

	copy(p, b)
	return len(p), nil
}

// Rand produces an io.Reader for random bytes from the remote Tao server.
func (t *TaoClient) Rand() io.Reader {
	return t
}

// GetRandomBytes returns a slice of n random bytes.
func (t *TaoClient) GetRandomBytes(n int) ([]byte, error) {
	r := &TaoRPCRequest{
		Rpc:  TaoRPCOperation_TAO_RPC_GET_RANDOM_BYTES.Enum(),
		Size: proto.Int32(int32(n)),
	}

	s := new(TaoRPCResponse)
	err := t.Parent.Call("TaoServer.GetRandomBytes", r, s)
	if err != nil {
		return nil, err
	}

	return s.Data, nil
}

// GetSharedSecret returns a slice of n secret bytes
func (t *TaoClient) GetSharedSecret(n int, policy string) ([]byte, error) {
	r := &TaoRPCRequest{
		Rpc:  TaoRPCOperation_TAO_RPC_GET_SHARED_SECRET.Enum(),
		Size: proto.Int32(int32(n)),
	}

	s := new(TaoRPCResponse)
	err := t.Parent.Call("TaoServer.GetSharedSecret", r, s)
	if err != nil {
		return nil, err
	}

	return s.Data, nil
}

// Attest requests the Tao host sign a Statement on behalf of the caller.
func (t *TaoClient) Attest(stmt *Statement) (*Attestation, error) {
	stData, err := proto.Marshal(stmt)
	if err != nil {
		return nil, err
	}

	r := &TaoRPCRequest{
		Rpc:  TaoRPCOperation_TAO_RPC_ATTEST.Enum(),
		Data: stData,
	}

	s := new(TaoRPCResponse)
	err = t.Parent.Call("TaoServer.Attest", r, s)
	if err != nil {
		return nil, err
	}

	a := new(Attestation)
	err = proto.Unmarshal(s.Data, a)
	if err != nil {
		return nil, err
	}

	return a, nil
}

// Seal encrypts data so only certain hosted programs can unseal it.
func (t *TaoClient) Seal(data []byte, policy string) ([]byte, error) {
	r := &TaoRPCRequest{
		Rpc:    TaoRPCOperation_TAO_RPC_SEAL.Enum(),
		Data:   data,
		Policy: proto.String(policy),
	}

	s := new(TaoRPCResponse)
	err := t.Parent.Call("TaoServer.Seal", r, s)
	if err != nil {
		return nil, err
	}

	return s.Data, nil
}

// Unseal decrypts data that has been sealed by the Seal() operation, but only
// if the policy specified during the Seal() operation is satisfied.
func (t *TaoClient) Unseal(sealed []byte) ([]byte, string, error) {
	r := &TaoRPCRequest{
		Rpc:  TaoRPCOperation_TAO_RPC_UNSEAL.Enum(),
		Data: sealed,
	}

	s := new(TaoRPCResponse)
	err := t.Parent.Call("TaoServer.Unseal", r, s)
	if err != nil {
		return nil, "", err
	}

	return s.Data, *s.Policy, nil
}
