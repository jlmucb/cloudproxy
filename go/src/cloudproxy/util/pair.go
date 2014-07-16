// File: pair.go
// Author: Kevin Walsh <kwalsh@holycross.edu>
// Description: Streams built from pairs of readers and writers.
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
	"io"
	"io/ioutil"
)

// A PairReadWriteCloser groups an io.ReadCloser and an io.WritCloser into a
// single structure that implements the io.ReadWriteCloser interface. This can
// be used to turn a pair of uni-directional streams into a single
// bi-directional stream.
type PairReadWriteCloser struct {
	io.ReadCloser
	io.WriteCloser
}

func (pair PairReadWriteCloser) Close() error {
	err1 := pair.ReadCloser.Close()
	err2 := pair.WriteCloser.Close()
	if err1 != nil {
		return err1
	} else {
		return err2
	}
}

func NewPairReadWriteCloser(r io.ReadCloser, w io.WriteCloser) *PairReadWriteCloser {
	if rw, _ := w.(io.ReadCloser); r == rw {
		return &PairReadWriteCloser{ioutil.NopCloser(r), w}
	} else {
		return &PairReadWriteCloser{r, w}
	}
}
