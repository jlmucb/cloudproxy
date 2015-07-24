// Copyright (c) 2015, Google Inc. All rights reserved.
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

package mixnet

import (
	"errors"
	"net"
)

const CellBytes = 1024 // Length of a cell

var errCellLength error = errors.New("incorrect cell length")

// Conn implements the net.Conn interface. The read and write operations are
// overloaded to check that only cells are sent between agents in the mixnet
// protocol.
type Conn struct {
	net.Conn
}

// Read a cell from the channel. Return an error if len(msg) != CellBytes.
func (c Conn) Read(msg []byte) (n int, err error) {
	n, err = c.Conn.Read(msg)
	if err != nil {
		return n, err
	}
	if n != CellBytes {
		return n, errCellLength
	}
	return n, nil
}

// Write a cell to the channel. If the len(msg) > CellBytes, return an error.
// If len(msg) < CellBytes, then zero-pad the message up to length of a cell.
func (c Conn) Write(msg []byte) (n int, err error) {
	cell := make([]byte, CellBytes) // Initialzed as an array of 0-bytes.
	if len(msg) > CellBytes {
		return 0, errCellLength
	}
	copy(cell, msg)
	n, err = c.Conn.Write(cell)
	if err != nil {
		return n, err
	}
	return n, nil
}
