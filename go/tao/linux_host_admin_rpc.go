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
func (client LinuxHostAdminClient) StartHostedProgram(spec *HostedProgramSpec) (auth.SubPrin, int, error) {
	req := &LinuxHostAdminRPCRequest{
		Path:          proto.String(spec.Path),
		Dir:           proto.String(spec.Dir),
		ContainerArgs: spec.ContainerArgs,
		Args:          spec.Args,
		// TODO: pass uid and gid?
	}
	var fds []int
	if spec.Stdin != nil {
		req.Stdin = proto.Int32(int32(len(fds)))
		fds = append(fds, int(spec.Stdin.Fd()))
	}
	if spec.Stdin != nil {
		req.Stdout = proto.Int32(int32(len(fds)))
		fds = append(fds, int(spec.Stdout.Fd()))
	}
	if spec.Stdin != nil {
		req.Stderr = proto.Int32(int32(len(fds)))
		fds = append(fds, int(spec.Stderr.Fd()))
	}
	resp := new(LinuxHostAdminRPCResponse)
	client.oob.ShareFDs(fds...)
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

// WaitHostedProgram is the client stub for LinuxHost.WaitHostedProgram.
func (client LinuxHostAdminClient) WaitHostedProgram(pid int, subprin auth.SubPrin) (int, error) {
	req := &LinuxHostAdminRPCRequest{
		Pid:     proto.Int32(int32(pid)),
		Subprin: auth.Marshal(subprin),
	}
	resp := new(LinuxHostAdminRPCResponse)
	err := client.Call("LinuxHost.WaitHostedProgram", req, resp)
	if err != nil {
		return -1, err
	}
	return int(*resp.Status), nil
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

// HostName is the client stub for LinuxHost.HostName.
func (client LinuxHostAdminClient) HostName() (auth.Prin, error) {
	req := &LinuxHostAdminRPCRequest{}
	resp := new(LinuxHostAdminRPCResponse)
	err := client.Call("LinuxHost.HostName", req, resp)
	if err != nil {
		return auth.Prin{}, err
	}
	return auth.UnmarshalPrin(resp.Prin)
}

// Shutdown is the client stub for LinuxHost.Shutdown.
func (client LinuxHostAdminClient) Shutdown() error {
	req := &LinuxHostAdminRPCRequest{}
	resp := new(LinuxHostAdminRPCResponse)
	return client.Call("LinuxHost.Shutdown", req, resp)
}

// LinuxHostAdminServer is a server stub for LinuxHost's admin RPC interface.
type LinuxHostAdminServer struct {
	lh   *LinuxHost
	Done chan bool
}

type linuxHostAdminServerStub struct {
	oob  *util.OOBUnixConn
	lh   *LinuxHost
	Done chan bool
}

// NewLinuxHostAdminServer returns a new server stub for LinuxHost's admin RPC
// interface.
func NewLinuxHostAdminServer(host *LinuxHost) LinuxHostAdminServer {
	return LinuxHostAdminServer{host, make(chan bool, 1)}
}

// StartHostedProgram is the server stub for LinuxHost.StartHostedProgram.
func (server linuxHostAdminServerStub) StartHostedProgram(r *LinuxHostAdminRPCRequest, s *LinuxHostAdminRPCResponse) error {
	files := server.oob.SharedFiles()
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	ucred := server.oob.PeerCred()
	if r.Path == nil {
		return newError("missing path")
	}
	spec := HostedProgramSpec{
		Path:          *r.Path,
		Args:          r.Args,
		ContainerArgs: r.ContainerArgs,
		Dir:           *r.Dir,
		Uid:           int(ucred.Uid),
		Gid:           int(ucred.Gid),
	}
	// We do allow superuser here, since we trust the oob credentials
	spec.Superuser = (ucred.Uid == 0 || ucred.Gid == 0)
	if r.Stdin != nil {
		if int(*r.Stdin) >= len(files) {
			return newError("missing stdin")
		}
		spec.Stdin = files[*r.Stdin]
	}
	if r.Stdout != nil {
		if int(*r.Stdout) >= len(files) {
			return newError("missing stdout")
		}
		spec.Stdout = files[*r.Stdout]
	}
	if r.Stderr != nil {
		if int(*r.Stderr) >= len(files) {
			return newError("missing stderr")
		}
		spec.Stderr = files[*r.Stderr]
	}
	subprin, pid, err := server.lh.StartHostedProgram(spec)
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
	ucred := server.oob.PeerCred()
	// TODO(kwalsh): also authorize owner of child
	if ucred.Uid != 0 && int(ucred.Uid) != os.Geteuid() {
		return newError("unauthorized: only root or owner can stop hosted programs")
	}
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

// WaitHostedProgram is the server stub for LinuxHost.WaitHostedProgram.
func (server linuxHostAdminServerStub) WaitHostedProgram(r *LinuxHostAdminRPCRequest, s *LinuxHostAdminRPCResponse) error {
	// ucred := server.oob.PeerCred()
	// TODO(kwalsh): also authorize owner of child
	// if ucred.Uid != 0 && int(ucred.Uid) != os.Geteuid() {
	// 	return newError("unauthorized: only root or owner can wait for hosted programs")
	// }
	if r.Pid == nil {
		return newError("required pid is nil")
	}
	pid := int(*r.Pid)
	subprin, err := auth.UnmarshalSubPrin(r.Subprin)
	if err != nil {
		return err
	}
	status, err := server.lh.WaitHostedProgram(pid, subprin)
	if err != nil {
		return err
	}
	s.Status = proto.Int32(int32(status))
	return nil
}

// KillHostedProgram is the server stub for LinuxHost.KillHostedProgram.
func (server linuxHostAdminServerStub) KillHostedProgram(r *LinuxHostAdminRPCRequest, s *LinuxHostAdminRPCResponse) error {
	ucred := server.oob.PeerCred()
	// TODO(kwalsh): also authorize owner of child
	if ucred.Uid != 0 && int(ucred.Uid) != os.Geteuid() {
		return newError("unauthorized: only root or owner can kill hosted programs")
	}
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

// Shutdown is the server stub for LinuxHost.Shutdown.
func (server linuxHostAdminServerStub) Shutdown(r *LinuxHostAdminRPCRequest, s *LinuxHostAdminRPCResponse) error {
	ucred := server.oob.PeerCred()
	// TODO(kwalsh): also authorize owner of child
	if ucred.Uid != 0 && int(ucred.Uid) != os.Geteuid() {
		return newError("unauthorized: only root or owner can shut down linux_host")
	}
	err := server.lh.Shutdown()
	server.Done <- true
	close(server.Done)
	return err
}

// Serve listens on sock for new connections and services them.
func (server LinuxHostAdminServer) Serve(sock *net.UnixListener) error {
	// Set the socket to allow peer credentials to be passed
	err := NewAuthenticatedFileSocket(sock);
	if err != nil {
		return err
	}

	connections := make(chan *net.UnixConn, 1)
	errors := make(chan error, 1)
	go func() {
		for {
			conn, err := sock.AcceptUnix()
			if err != nil {
				errors <- err
				break
			}
			connections <- conn
		}
	}()

	for {
		var conn *net.UnixConn
		select {
		case conn = <-connections:
			break
		case err = <-errors:
			return err
		case <-server.Done:
			return nil
		}
		s := rpc.NewServer()
		oob := util.NewOOBUnixConn(conn)
		err = s.RegisterName("LinuxHost", linuxHostAdminServerStub{oob, server.lh, server.Done})
		if err != nil {
			return err
		}
		go s.ServeCodec(protorpc.NewServerCodec(oob))
	}
}
