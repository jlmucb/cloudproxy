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
	m        sync.Mutex // protects recvFDs, sendFDs, and peerCred
	recvFDs  []int
	sendFDs  []int
	peerCred *syscall.Ucred
	*net.UnixConn
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

// SharedFDs retreives the file descriptors shared during recent Read calls.
func (s *OOBUnixConn) SharedFDs() []int {
	var fds []int
	s.m.Lock()
	fds = s.recvFDs
	s.recvFDs = nil
	s.m.Unlock()
	return fds
}

// PeerCred retreives the most recently passed peer credential, or nil if no
// credentials have been received yet.
func (s *OOBUnixConn) PeerCred() *syscall.Ucred {
	s.m.Lock()
	defer s.m.Unlock()
	return s.peerCred
}

func (s *OOBUnixConn) Write(buf []byte) (int, error) {
	var oob []byte
	var fds []int
	s.m.Lock()
	fds = s.sendFDs
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

func (s *OOBUnixConn) Read(p []byte) (n int, err error) {
	var oob [OOBMaxLength]byte
	n, oobn, _, _, err := s.ReadMsgUnix(p, oob[:])
	if err == nil && n > 0 && oobn > 0 {
		scm, err := syscall.ParseSocketControlMessage(oob[0:oobn])
		if err != nil {
			return n, err
		}
		s.m.Lock()
		for _, m := range scm {
			if fds, err := syscall.ParseUnixRights(&m); err == nil {
				s.recvFDs = append(s.recvFDs, fds...)
			} else if ucred, err := syscall.ParseUnixCredentials(&m); err == nil {
				s.peerCred = ucred
			}
		}
		s.m.Unlock()
	}
	return n, err
}
