// Copyright (c) 2014, Google, Inc. All rights reserved.
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

type ChanReadWriteCloser struct {
	R <-chan []byte
	W chan []byte
}

func (crw ChanReadWriteCloser) Read(p []byte) (int, error) {
	return copy(p, <-crw.R), nil
}

func (crw ChanReadWriteCloser) Write(p []byte) (int, error) {
	crw.W <- p
	return len(p), nil
}

func (crw ChanReadWriteCloser) Close() error {
	close(crw.W)
	return nil
}
