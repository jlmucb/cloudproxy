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
	"io"
	"os/exec"

	"code.google.com/p/goprotobuf/proto"
)

// A LinuxHostServer wraps a LinuxHost and serves its methods across a net/rpc
// connection to a hosted program.
type LinuxHostServer struct {
	host         *LinuxHost
	channel      io.ReadWriteCloser
	ChildSubprin auth.SubPrin
	Cmd          *exec.Cmd
}

// GetTaoName returns the Tao principal name assigned to the caller.
func (lhs *LinuxHostServer) GetTaoName(r *TaoRPCRequest, s *TaoRPCResponse) error {
	s.Data = []byte(lhs.host.handleGetTaoName(lhs.ChildSubprin))
	return nil
}

// ExtendTaoName irreversibly extends the Tao principal name of the caller.
// TODO(kwalsh): do sanity checking on r.Data
func (lhs *LinuxHostServer) ExtendTaoName(r *TaoRPCRequest, s *TaoRPCResponse) error {
	ext, err := auth.UnmarshalSubPrin(r.Data)
	if err != nil {
		return err
	}
	lhs.ChildSubprin = append(lhs.ChildSubprin, ext...)
	return nil
}

// GetRandomBytes returns a slice of n random bytes.
func (lhs *LinuxHostServer) GetRandomBytes(r *TaoRPCRequest, s *TaoRPCResponse) error {
	if r.Size == nil || *r.Size <= 0 {
		return errors.New("Invalid array size")
	}

	var err error
	s.Data, err = lhs.host.handleGetRandomBytes(lhs.ChildSubprin, int(*r.Size))
	if err != nil {
		return err
	}

	return nil
}

// GetSharedSecret returns a slice of n secret bytes.
func (lhs *LinuxHostServer) GetSharedSecret(r *TaoRPCRequest, s *TaoRPCResponse) error {
	var err error
	if r.Size == nil {
		return errors.New("must supply a Size to GetSharedSecret")
	}

	s.Data, err = lhs.host.handleGetSharedSecret(lhs.ChildSubprin, int(*r.Size), string(r.Data))
	if err != nil {
		return err
	}

	return nil
}

// Seal encrypts data so only certain hosted programs can unseal it.
func (lhs *LinuxHostServer) Seal(r *TaoRPCRequest, s *TaoRPCResponse) error {
	var err error
	if r.Policy == nil {
		return errors.New("must supply a Policy to Seal")
	}

	s.Data, err = lhs.host.handleSeal(lhs.ChildSubprin, r.Data, *r.Policy)
	if err != nil {
		return err
	}

	return nil
}

// Unseal decrypts data that has been sealed by the Seal() operation, but only
// if the policy specified during the Seal() operation is satisfied.
func (lhs *LinuxHostServer) Unseal(r *TaoRPCRequest, s *TaoRPCResponse) error {
	var err error
	var policy string
	s.Data, policy, err = lhs.host.handleUnseal(lhs.ChildSubprin, r.Data)
	if err != nil {
		return err
	}

	s.Policy = proto.String(policy)
	return nil
}

// Attest requests the Tao host sign a statement on behalf of the caller.
func (lhs *LinuxHostServer) Attest(r *TaoRPCRequest, s *TaoRPCResponse) error {
	stmt, err := auth.UnmarshalForm(r.Data)
	if err != nil {
		return err
	}

	var issuer *auth.Prin
	if r.Issuer != nil {
		t, err := auth.UnmarshalTerm(*r.Issuer)
		if err != nil {
			return err
		}
		p, ok := t.(Prin)
		if !ok {
			return errors.New("issuer must a principal or nil")
		}
		issuer = &p
	}

	a, err := lhs.host.handleAttest(lhs.ChildSubprin, issuer, r.Time, r.Expiration, stmt)
	if err != nil {
		return err
	}

	s.Data, err = proto.Marshal(a)
	return err
}
