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
	"errors"

	"code.google.com/p/goprotobuf/proto"
)

// A TaoServer wraps a Tao and serves its methods across a net/rpc connection.
type TaoServer struct {
	T Tao
}

// GetTaoName returns the Tao principal name assigned to the caller.
func (ts *TaoServer) GetTaoName(r *TaoRPCRequest, s *TaoRPCResponse) error {
	name, err := ts.T.GetTaoName()
	if err != nil {
		return err
	}

	s.Data = []byte(name)
	return nil
}

// ExtendTaoName irreversibly extends the Tao principal name of the caller.
func (ts *TaoServer) ExtendTaoName(r *TaoRPCRequest, s *TaoRPCResponse) error {
	if err := ts.T.ExtendTaoName(string(r.Data)); err != nil {
		return err
	}

	return nil
}

// GetRandomBytes returns a slice of n random bytes.
func (ts *TaoServer) GetRandomBytes(r *TaoRPCRequest, s *TaoRPCResponse) error {
	if r.GetSize() <= 0 {
		return errors.New("Invalid array size")
	}

	var err error
	s.Data, err = ts.T.GetRandomBytes(int(r.GetSize()))
	if err != nil {
		return err
	}

	return nil
}

// Rand produces an io.Reader for random bytes from this Tao.  This should
// never be called on the TaoServer, since it's handled transparently by
// TaoClient.
func (ts *TaoServer) Rand(r *TaoRPCRequest, s *TaoRPCResponse) error {
	return nil
}

// GetSharedSecret returns a slice of n secret bytes.
func (ts *TaoServer) GetSharedSecret(r *TaoRPCRequest, s *TaoRPCResponse) error {
	var err error
	s.Data, err = ts.T.GetSharedSecret(int(*r.Size), string(r.Data))
	if err != nil {
		return err
	}

	return nil
}

// Seal encrypts data so only certain hosted programs can unseal it.
func (ts *TaoServer) Seal(r *TaoRPCRequest, s *TaoRPCResponse) error {
	var err error
	s.Data, err = ts.T.Seal(r.Data, *r.Policy)
	if err != nil {
		return err
	}

	return nil
}

// Unseal decrypts data that has been sealed by the Seal() operation, but only
// if the policy specified during the Seal() operation is satisfied.
func (ts *TaoServer) Unseal(r *TaoRPCRequest, s *TaoRPCResponse) error {
	var err error
	var policy string
	s.Data, policy, err = ts.T.Unseal(r.Data)
	if err != nil {
		return err
	}

	s.Policy = proto.String(policy)
	return nil
}

// Attest requests the Tao host sign a Statement on behalf of the caller.
func (ts *TaoServer) Attest(r *TaoRPCRequest, s *TaoRPCResponse) error {
	stmt := new(Statement)
	err := proto.Unmarshal(r.Data, stmt)
	if err != nil {
		return err
	}

	a, err := ts.T.Attest(stmt)
	if err != nil {
		return err
	}

	s.Data, err = proto.Marshal(a)
	return err
}
