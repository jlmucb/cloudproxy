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
	"io"
	"os"
	"syscall"
)

// NewFile wraps a file descriptor inside an os.File, also giving it a
// reasonable name.
func NewFile(fd int) *os.File {
	name := fmt.Sprintf("/dev/fd/%d", fd)
	return os.NewFile(uintptr(fd), name)
}

// NewFiles wraps each file descriptor inside an os.File, giving each a
// reasonable name.
func NewFiles(fds []int) []*os.File {
	files := make([]*os.File, len(fds))
	for i, fd := range fds {
		files[i] = NewFile(fd)
	}
	return files
}

// NewStdio wraps each file descriptor in an os.File then returns the first
// three as stdin, stdout, stderr, and the remainder as extra. If there are less
// than three file descriptors, the corresponding values from os.Stdin,
// os.Stdout, and os.Stderr are returned.
func NewStdio(fds []int) (stdin io.Reader, stdout io.Writer, stderr io.Writer, extra []*os.File) {
	if len(fds) > 0 {
		stdin = NewFile(fds[0])
	} else {
		stdin = os.Stdin // TODO(kwalsh) use nil instead?
	}
	if len(fds) > 1 {
		stdout = NewFile(fds[1])
	} else {
		stdout = os.Stdout // TODO(kwalsh) use nil instead?
	}
	if len(fds) > 2 {
		stderr = NewFile(fds[2])
	} else {
		stderr = os.Stderr // TODO(kwalsh) use nil instead?
	}
	for i := 3; i < len(fds); i++ {
		extra = append(extra, NewFile(fds[i]))
	}
	return
}

// CloseFDs closes each of the file descriptors.
func CloseFDs(fds []int) {
	for _, f := range fds {
		NewFile(f).Close()
	}
}

// IsValidFD uses the fcntl(F_GETFD) system call to check whether a file
// descriptor is valid.
func IsValidFD(fd int) bool {
	flags, _, err := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
	return int(flags) != -1 || err != syscall.EBADF
}
