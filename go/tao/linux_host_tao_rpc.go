// Copyright (c) 2014, Google Inc.  All rights reserved.
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

// This provides a server stub for LinuxHost's Tao RPC interface. This code is
// (mostly) extremely dull and, ideally, would be generated automatically. The
// only mildly interesting thing it does is hold some state associated with each
// connection, and pass that as a parameter to each server function.

import (
	"io"
	"net/rpc"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util/protorpc"
)

// LinuxHostTaoServer is a server stub for LinuxHost's Tao RPC interface.
type LinuxHostTaoServer struct {
	lh    *LinuxHost
	child HostedProgram
}

type linuxHostTaoServerStub LinuxHostTaoServer

// NewLinuxHostTaoServer returns a new server stub for LinuxHost's Tao RPC
// interface.
func NewLinuxHostTaoServer(host *LinuxHost, child HostedProgram) LinuxHostTaoServer {
	return LinuxHostTaoServer{host, child}
}

// Serve listens on sock for new connections and services them.
func (server LinuxHostTaoServer) Serve(conn io.ReadWriteCloser) error {
	s := rpc.NewServer()
	err := s.RegisterName("Tao", linuxHostTaoServerStub(server))
	if err != nil {
		return err
	}
	s.ServeCodec(protorpc.NewServerCodec(conn))
	return nil
}

// GetTaoName is the server stub for Tao.GetTaoName.
func (server linuxHostTaoServerStub) GetTaoName(r *RPCRequest, s *RPCResponse) error {
	s.Data = auth.Marshal(server.lh.GetTaoName(server.child))
	return nil
}

// ExtendTaoName is the server stub for Tao.ExtendTaoName.
func (server linuxHostTaoServerStub) ExtendTaoName(r *RPCRequest, s *RPCResponse) error {
	ext, err := auth.UnmarshalSubPrin(r.Data)
	if err != nil {
		return err
	}
	return server.lh.ExtendTaoName(server.child, ext)
}

// GetRandomBytes is the server stub for Tao.GetRandomBytes.
func (server linuxHostTaoServerStub) GetRandomBytes(r *RPCRequest, s *RPCResponse) error {
	if r.Size == nil || *r.Size <= 0 {
		return newError("invalid size")
	}
	data, err := server.lh.GetRandomBytes(server.child, int(*r.Size))
	s.Data = data
	return err
}

// GetSharedSecret is the server stub for Tao.GetSharedSecret.
func (server linuxHostTaoServerStub) GetSharedSecret(r *RPCRequest, s *RPCResponse) error {
	if r.Size == nil || *r.Size <= 0 {
		return newError("invalid size")
	}
	if r.Policy == nil {
		return newError("missing policy")
	}
	data, err := server.lh.GetSharedSecret(server.child, int(*r.Size), *r.Policy)
	s.Data = data
	return err
}

// Seal is the server stub for Tao.Seal.
func (server linuxHostTaoServerStub) Seal(r *RPCRequest, s *RPCResponse) error {
	if r.Policy == nil {
		return newError("missing policy")
	}
	data, err := server.lh.Seal(server.child, r.Data, *r.Policy)
	s.Data = data
	return err
}

// Unseal is the server stub for Tao.Unseal.
func (server linuxHostTaoServerStub) Unseal(r *RPCRequest, s *RPCResponse) error {
	data, policy, err := server.lh.Unseal(server.child, r.Data)
	s.Data = data
	s.Policy = proto.String(policy)
	return err
}

// Attest is the server stub for Tao.Attest.
func (server linuxHostTaoServerStub) Attest(r *RPCRequest, s *RPCResponse) error {
	stmt, err := auth.UnmarshalForm(r.Data)
	if err != nil {
		return err
	}
	var issuer *auth.Prin
	if r.Issuer != nil {
		p, err := auth.UnmarshalPrin(r.Issuer)
		if err != nil {
			return err
		}
		issuer = &p
	}
	a, err := server.lh.Attest(server.child, issuer, r.Time, r.Expiration, stmt)
	if err != nil {
		return err
	}
	s.Data, err = proto.Marshal(a)
	return err
}
