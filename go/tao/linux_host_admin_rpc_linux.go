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


// Serve listens on sock for new connections and services them.
func (server LinuxHostAdminServer) Serve(sock *net.UnixListener) error {
	// Set the socket to allow peer credentials to be passed
	sockFile, err := sock.File()
	if err != nil {
		return err
	}
	err = syscall.SetsockoptInt(int(sockFile.Fd()), syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1 /* true */)
	sockFile.Close()
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
