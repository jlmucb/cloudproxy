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
)

// NewFile wraps a file descriptor inside an os.File, also giving it a
// reasonable name.
func NewFile(fd int) *os.File {
	name := fmt.Sprintf("/dev/fd/%d", fd)
	return os.NewFile(uintptr(fd), name)
}

// NewStdio splits the list of files. The first three are taken as stdin,
// stdout, stderr, and the remainder as extra. If there are less than three
// files, nil is used instead.
func NewStdio(files []*os.File) (stdin io.Reader, stdout io.Writer, stderr io.Writer, extra []*os.File) {
	if len(files) > 0 {
		stdin = files[0]
	}
	if len(files) > 1 {
		stdout = files[1]
	}
	if len(files) > 2 {
		stderr = files[2]
	}
	if len(files) > 3 {
		extra = files[3:]
	}
	return
}
