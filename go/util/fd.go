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

// This provides a convenience functions for dealing with file descriptors.

import (
	"fmt"
	"os"
	"syscall"
)

// NewFile wraps a file descriptor inside an os.File, also giving it a
// reasonable name.
func NewFile(fd int) *os.File {
	name := fmt.Sprintf("/dev/fd/%d", fd)
	return os.NewFile(uintptr(fd), name)
}

// IsValidFD uses the fcntl(F_GETFD) system call to check whether a file
// descriptor is valid.
func IsValidFD(fd int) bool {
	flags, _, err := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
	return int(flags) != -1 || err != syscall.EBADF
}
