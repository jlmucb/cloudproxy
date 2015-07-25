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
	"net"
	"net/rpc"
	"os"
	"syscall"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/util/protorpc"
)

// LinuxHostAdminClient is a client stub for LinuxHost's admin RPC interface.
type LinuxHostAdminClient struct {
	oob *util.OOBUnixConn
	*rpc.Client
}

// NewLinuxHostAdminClient returns a new client stub for LinuxHost's admin RPC
// interface.
func NewLinuxHostAdminClient(conn *net.UnixConn) LinuxHostAdminClient {
	oob := util.NewOOBUnixConn(conn)
	c := rpc.NewClientWithCodec(protorpc.NewClientCodec(oob))
	return LinuxHostAdminClient{oob, c}
}

// StartHostedProgram is the client stub for LinuxHost.StartHostedProgram.
func (client LinuxHostAdminClient) StartHostedProgram(path string, args ...string) (auth.SubPrin, int, error) {
	req := &LinuxHostAdminRPCRequest{
		Path: proto.String(path),
		Args: args,
	}
	resp := new(LinuxHostAdminRPCResponse)
	// TODO(kwalsh) If any stdio files are closed, this code will likely fail:
	// Fd() will return ^uintptr(0) and OOB probably chokes on that. We need to
	// send 3 fds, so maybe open /dev/null for such cases, then close it after.
	// Todo(kwalsh) Consider making oob use uintptr for file descriptors to
	// avoid the conversions here, at the cost of performing conversions
	// elsehwere. Go is inconsistent, using both int and uintptr for file
	// descriptors in different places.
	client.oob.ShareFDs(int(os.Stdin.Fd()), int(os.Stdout.Fd()), int(os.Stderr.Fd()))
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

// HostName is the client stub for LinuxHost.HostName..
func (client LinuxHostAdminClient) HostName() (auth.Prin, error) {
	req := &LinuxHostAdminRPCRequest{}
	resp := new(LinuxHostAdminRPCResponse)
	err := client.Call("LinuxHost.HostName", req, resp)
	if err != nil {
		return auth.Prin{}, err
	}
	return auth.UnmarshalPrin(resp.Prin)
}

// LinuxHostAdminServer is a server stub for LinuxHost's admin RPC interface.
type LinuxHostAdminServer struct {
	lh *LinuxHost
}

type linuxHostAdminServerStub struct {
	oob *util.OOBUnixConn
	lh  *LinuxHost
}

// NewLinuxHostAdminServer returns a new server stub for LinuxHost's admin RPC
// interface.
func NewLinuxHostAdminServer(host *LinuxHost) LinuxHostAdminServer {
	return LinuxHostAdminServer{host}
}

// Serve listens on sock for new connections and services them.
func (server LinuxHostAdminServer) Serve(sock *net.UnixListener) error {
	// Set the socket to allow peer credentials to be passed
	sockFile, err := sock.File()
	if err != nil {
		return err
	}
	err = syscall.SetsockoptInt(int(sockFile.Fd()), syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1 /* true */)
	if err != nil {
		sockFile.Close()
		return err
	}
	sockFile.Close()

	for {
		conn, err := sock.AcceptUnix()
		if err != nil {
			return err
		}
		s := rpc.NewServer()
		oob := util.NewOOBUnixConn(conn)
		err = s.RegisterName("LinuxHost", linuxHostAdminServerStub{oob, server.lh})
		if err != nil {
			return err
		}
		go s.ServeCodec(protorpc.NewServerCodec(oob))
	}
}

// StartHostedProgram is the server stub for LinuxHost.StartHostedProgram.
func (server linuxHostAdminServerStub) StartHostedProgram(r *LinuxHostAdminRPCRequest, s *LinuxHostAdminRPCResponse) error {
	fds := server.oob.SharedFDs()
	defer util.CloseFDs(fds)
	ucred := server.oob.PeerCred()
	if r.Path == nil {
		return newError("missing path")
	}
	subprin, pid, err := server.lh.StartHostedProgram(*r.Path, r.Args, int(ucred.Uid), int(ucred.Gid), fds)
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

// HostName is the server stub for LinuxHost.HostName.
func (server linuxHostAdminServerStub) HostName(r *LinuxHostAdminRPCRequest, s *LinuxHostAdminRPCResponse) error {
	prin := server.lh.HostName()
	s.Prin = auth.Marshal(prin)
	return nil
}
