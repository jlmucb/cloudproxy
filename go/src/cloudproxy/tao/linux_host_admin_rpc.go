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

// This provides client and server stubs for LinuxHost's admin RPC interface.
// This code is extremely dull and, ideally, would be generated automatically.

import (
	"io"
	"net"
	"net/rpc"

	"code.google.com/p/goprotobuf/proto"

	"cloudproxy/tao/auth"
	"cloudproxy/util/protorpc"
)

// LinuxHostAdminClient is a client stub for LinuxHost's admin RPC interface.
type LinuxHostAdminClient struct {
	*rpc.Client
}

// NewLinuxHostAdminClient returns a new client stub for LinuxHost's admin RPC
// interface.
func NewLinuxHostAdminClient(conn io.ReadWriteCloser) LinuxHostAdminClient {
	c := rpc.NewClientWithCodec(protorpc.NewClientCodec(conn))
	return LinuxHostAdminClient{c}
}

// StartHostedProgram is the client stub for LinuxHost.StartHostedProgram.
func (client LinuxHostAdminClient) StartHostedProgram(path string, args ...string) (auth.SubPrin, int, error) {
	req := &LinuxHostAdminRPCRequest{
		Path: proto.String(path),
		Args: args,
	}
	resp := new(LinuxHostAdminRPCResponse)
	err := client.Call("LinuxHost.StartHostedProgram", req, resp)
	if err != nil {
		return auth.SubPrin{}, 0, err
	}
	if len(resp.Child) != 1 {
		return auth.SubPrin{}, 0, newError("invalid response")
	}
	subprin, err := auth.UnmarshalSubPrin(resp.Child[0].Subprin)
	return subprin, int(*resp.Child[0].Pid), err
}

// StopHostedProgram is the client stub for LinuxHost.StopHostedProgram.
func (client LinuxHostAdminClient) StopHostedProgram(subprin auth.SubPrin) error {
	req := &LinuxHostAdminRPCRequest{
		Subprin: auth.Marshal(subprin),
	}
	resp := new(LinuxHostAdminRPCResponse)
	err := client.Call("LinuxHost.StopHostedProgram", req, resp)
	if err != nil {
		return err
	}
	return nil
}

// ListHostedPrograms is the client stub for LinuxHost.ListHostedPrograms.
func (client LinuxHostAdminClient) ListHostedPrograms() (name []auth.SubPrin, pid []int, err error) {
	req := &LinuxHostAdminRPCRequest{}
	resp := new(LinuxHostAdminRPCResponse)
	err = client.Call("LinuxHost.ListHostedPrograms", req, resp)
	if err != nil {
		return nil, nil, err
	}
	name = make([]auth.SubPrin, len(resp.Child))
	pid = make([]int, len(resp.Child))
	for i, child := range resp.Child {
		pid[i] = int(*child.Pid)
		name[i], err = auth.UnmarshalSubPrin(child.Subprin)
		if err != nil {
			return nil, nil, err
		}
	}
	return name, pid, nil
}

// KillHostedProgram is the client stub for LinuxHost.KillHostedProgram.
func (client LinuxHostAdminClient) KillHostedProgram(subprin auth.SubPrin) error {
	req := &LinuxHostAdminRPCRequest{
		Subprin: auth.Marshal(subprin),
	}
	resp := new(LinuxHostAdminRPCResponse)
	err := client.Call("LinuxHost.KillHostedProgram", req, resp)
	if err != nil {
		return err
	}
	return nil
}

// TaoHostName is the client stub for LinuxHost.TaoHostName..
func (client LinuxHostAdminClient) TaoHostName() (auth.Prin, error) {
	req := &LinuxHostAdminRPCRequest{}
	resp := new(LinuxHostAdminRPCResponse)
	err := client.Call("LinuxHost.TaoHostName", req, resp)
	if err != nil {
		return auth.Prin{}, err
	}
	return auth.UnmarshalPrin(resp.Prin)
}

// LinuxHostAdminServer is a server stub for LinuxHost's admin RPC interface.
type LinuxHostAdminServer struct {
	lh *LinuxHost
}

type linuxHostAdminServerStub LinuxHostAdminServer

// NewLinuxHostAdminServer returns a new server stub for LinuxHost's admin RPC
// interface.
func NewLinuxHostAdminServer(host *LinuxHost) LinuxHostAdminServer {
	return LinuxHostAdminServer{host}
}

// Serve listens on sock for new connections and services them.
func (server LinuxHostAdminServer) Serve(sock net.Listener) error {
	for {
		conn, err := sock.Accept()
		if err != nil {
			return err
		}
		s := rpc.NewServer()
		err = s.RegisterName("LinuxHost", linuxHostAdminServerStub(server))
		if err != nil {
			return err
		}
		go s.ServeCodec(protorpc.NewServerCodec(conn))
	}
}

// StartHostedProgram is the server stub for LinuxHost.StartHostedProgram.
func (server linuxHostAdminServerStub) StartHostedProgram(r *LinuxHostAdminRPCRequest, s *LinuxHostAdminRPCResponse) error {
	if r.Path == nil {
		return newError("missing path")
	}
	subprin, pid, err := server.lh.StartHostedProgram(*r.Path, r.Args)
	if err != nil {
		return err
	}
	s.Child = make([]*LinuxHostAdminRPCHostedProgram, 1)
	s.Child[0] = &LinuxHostAdminRPCHostedProgram{
		Subprin: auth.Marshal(subprin),
		Pid:     proto.Int32(int32(pid)),
	}
	return nil
}

// StopHostedProgram is the server stub for LinuxHost.StopHostedProgram.
func (server linuxHostAdminServerStub) StopHostedProgram(r *LinuxHostAdminRPCRequest, s *LinuxHostAdminRPCResponse) error {
	subprin, err := auth.UnmarshalSubPrin(r.Subprin)
	if err != nil {
		return err
	}
	return server.lh.StopHostedProgram(subprin)
}

// ListHostedPrograms is the server stub for LinuxHost.ListHostedPrograms.
func (server linuxHostAdminServerStub) ListHostedPrograms(r *LinuxHostAdminRPCRequest, s *LinuxHostAdminRPCResponse) error {
	names, pids, err := server.lh.ListHostedPrograms()
	if err != nil {
		return err
	}
	if len(names) != len(pids) {
		return newError("invalid response")
	}
	s.Child = make([]*LinuxHostAdminRPCHostedProgram, len(names))
	for i := range names {
		s.Child[i] = &LinuxHostAdminRPCHostedProgram{
			Subprin: auth.Marshal(names[i]),
			Pid:     proto.Int32(int32(pids[i])),
		}
	}
	return nil
}

// KillHostedProgram is the server stub for LinuxHost.KillHostedProgram.
func (server linuxHostAdminServerStub) KillHostedProgram(r *LinuxHostAdminRPCRequest, s *LinuxHostAdminRPCResponse) error {
	subprin, err := auth.UnmarshalSubPrin(r.Subprin)
	if err != nil {
		return err
	}
	return server.lh.KillHostedProgram(subprin)
}

// TaoHostName is the server stub for LinuxHost.TaoHostName.
func (server linuxHostAdminServerStub) TaoHostName(r *LinuxHostAdminRPCRequest, s *LinuxHostAdminRPCResponse) error {
	prin := server.lh.TaoHostName()
	s.Prin = auth.Marshal(prin)
	return nil
}
