// Copyright (c) 2015, Kevin Walsh.  All rights reserved.
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

// This provides a version of UnixConn that can inject and collect out-of-band
// data, specifically, credentials and file descriptors.

import (
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
)

// Error types for the protorpc package.
var (
	ErrOOBSendFailed  = errors.New("error sending out-of-band unix socket data")
	ErrOOBParseFailed = errors.New("error parsing out-of-band unix socket data")
)

// Maximum amount of out-of-band data supported. This is enough to send
// at least a set of credentials and 3 file descriptors.
const OOBMaxLength = 100 // usually under 64 in practice

// OOBUnixConn provides the same operations as net.UnixConn, plus the ability to
// asynchronously make use of the out-of-band mechanism to share file descriptors
// and credentials.
type OOBUnixConn struct {
	m         sync.Mutex // protects recvFiles, sendFDs, and peerCred
	recvFiles []*os.File
	sendFDs   []int
	peerCred  *Ucred
	*net.UnixConn
}

// Ucred holds credentials of a peer process.
type Ucred struct {
	Uid uint32
	Gid uint32
}

// NewOOBUnixConn returns a new util.OOBUnixConn, which provides the same
// operations as net.UnixConn but also allows sharing of file descriptors and
// credentials.
func NewOOBUnixConn(conn *net.UnixConn) *OOBUnixConn {
	return &OOBUnixConn{UnixConn: conn}
}

// ShareFDs adds some file descriptors to the list of filescriptors to be
// shared during the next Write.
func (s *OOBUnixConn) ShareFDs(fd ...int) {
	s.m.Lock()
	s.sendFDs = append(s.sendFDs, fd...)
	s.m.Unlock()
}

// SharedFiles retreives the open files shared during recent Read calls.
func (s *OOBUnixConn) SharedFiles() []*os.File {
	s.m.Lock()
	fds := s.recvFiles
	s.recvFiles = nil
	s.m.Unlock()
	return fds
}

func (s *OOBUnixConn) Write(buf []byte) (int, error) {
	var oob []byte
	s.m.Lock()
	fds := s.sendFDs
	s.sendFDs = nil
	s.m.Unlock()
	if len(fds) > 0 {
		oob = syscall.UnixRights(fds...)
	}
	n, oobn, err := s.WriteMsgUnix(buf, oob, nil)
	if err == nil && oobn != len(oob) {
		err = ErrOOBSendFailed
	}
	return n, err
}
