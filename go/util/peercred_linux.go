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
	"syscall"
)

// PeerCred retreives the most recently passed peer credential, or nil if no
// credentials have been received yet.
func (s *OOBUnixConn) PeerCred() *Ucred {
	s.m.Lock()
	defer s.m.Unlock()
	return s.peerCred
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
			if m.Header.Level != syscall.SOL_SOCKET {
				continue
			}
			switch m.Header.Type {
			case syscall.SCM_RIGHTS:
				if fds, err := syscall.ParseUnixRights(&m); err == nil {
					for _, fd := range fds {
						// Note: We wrap the raw FDs inside an os.File just
						// once, early, to prevent double-free or leaking FDs.
						f := NewFile(fd)
						s.recvFiles = append(s.recvFiles, f)
					}
				}
			case syscall.SCM_CREDENTIALS:
				if ucred, err := syscall.ParseUnixCredentials(&m); err == nil {
					s.peerCred = &Ucred{Uid: ucred.Uid, Gid: ucred.Gid}
				}
			}
		}
		s.m.Unlock()
	}
	return n, err
}
