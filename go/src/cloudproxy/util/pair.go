// Description: Streams built from pairs of readers and writers.
//
// Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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
	"io"
	"io/ioutil"
)

// A PairReadWriteCloser groups an io.ReadCloser and an io.WriteCloser into a
// single structure that implements the io.ReadWriteCloser interface. This can
// be used to turn a pair of uni-directional streams into a single
// bi-directional stream.
type PairReadWriteCloser struct {
	io.ReadCloser
	io.WriteCloser
}

// Close closes the underying streams, both the io.ReadCloser and the
// io.WriteCloser.
func (pair PairReadWriteCloser) Close() error {
	err1 := pair.ReadCloser.Close()
	err2 := pair.WriteCloser.Close()
	if err1 != nil {
		return err1
	} else {
		return err2
	}
}

// NewPairReadWriteCloser creates a new io.ReadWriteCloser given separate
// streams for reading and writing. If both streams refer to the same object,
// then the read stream will be wrapped in an ioutil.NopCloser() so that Close()
// on the resulting io.ReadWriteCloser() will only close that underlying stream
// object once.
func NewPairReadWriteCloser(r io.ReadCloser, w io.WriteCloser) *PairReadWriteCloser {
	if rw, _ := w.(io.ReadCloser); r == rw {
		return &PairReadWriteCloser{ioutil.NopCloser(r), w}
	} else {
		return &PairReadWriteCloser{r, w}
	}
}
