// File: fdmessagestream.go
// Author: Kevin Walsh <kwalsh@holycross.edu>
// Description: Helper for making fd-based message streams
//
// Copyright (c) 2013, Google Inc.  All rights reserved.
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
	"errors"
	"fmt"
	"os"
)

// DeserializeFDMessageStream takes a string description of the form
// "tao::FDMessageStream(X, Y)" and returns a MessageStream that uses file
// descriptor X as the reader and file descriptor Y as the writer.
func DeserializeFDMessageStream(s string) (*MessageStream, error) {
	var readfd, writefd uintptr
	_, err := fmt.Sscanf(s, "tao::FDMessageChannel(%d, %d)", &readfd, &writefd)
	if err != nil {
		return nil, errors.New("unrecognized channel spec " + s)
	}
	if readfd == writefd {
		rw := os.NewFile(readfd, "read/write pipe")
		return NewMessageStream(rw), nil
	} else {
		r := os.NewFile(readfd, "read pipe")
		w := os.NewFile(writefd, "write pipe")
		rw := NewPairReadWriteCloser(r, w)
		return NewMessageStream(rw), nil
	}
}

