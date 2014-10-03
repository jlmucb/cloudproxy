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

package util

import (
	"fmt"
	"io"
	"net"
	"os"
)

// A UnixSingleReadWriteCloser accepts a single connection and reads and writes
// to this connection
type UnixSingleReadWriteCloser struct {
	l net.Listener
	c net.Conn
}

// NewUnixSingleReadWriteCloser listens on a given Unix socket path and returns
// a UnixSingleReadWriteCloser that will accept a single connection on this
// socket and communicate only with it.
func NewUnixSingleReadWriteCloser(path string) io.ReadWriteCloser {
	l, err := net.Listen("unix", path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to listen on the channel: %s\n", err)
		return nil
	}

	return &UnixSingleReadWriteCloser{l, nil}
}

// Read accepts a connection if there isn't one already and reads from the
// connection.
func (usrwc *UnixSingleReadWriteCloser) Read(p []byte) (int, error) {
	var err error
	if usrwc.c == nil {
		usrwc.c, err = usrwc.l.Accept()
		if err != nil {
			return 0, err
		}
	}

	return usrwc.c.Read(p)
}

// Write accepts a connection if there isn't one already and writes to the
// connection.
func (usrwc *UnixSingleReadWriteCloser) Write(p []byte) (int, error) {
	var err error
	if usrwc.c == nil {
		usrwc.c, err = usrwc.l.Accept()
		if err != nil {
			return 0, err
		}
	}

	return usrwc.c.Write(p)
}

// Close closes the connection if there is one and closes the listener.
func (usrwc *UnixSingleReadWriteCloser) Close() error {
	if usrwc.c != nil {
		usrwc.c.Close()
	}

	return usrwc.l.Close()
}
