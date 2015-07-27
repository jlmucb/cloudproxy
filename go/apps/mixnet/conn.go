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
	"encoding/binary"
	"errors"
	"net"

	"github.com/golang/protobuf/proto"
)

const (
	CellBytes   = 1 << 10 // Length of a cell
	MaxMsgBytes = 1 << 16 // Maximum length of a message
)

const (
	msgCell = iota
	dirCell
	relayCell
)

var errCellLength error = errors.New("incorrect cell length")
var errBadCellType error = errors.New("unrecognized cell type")
var errBadDirective error = errors.New("received bad directive")
var errMsgLength error = errors.New("message too long")

// Conn implements the net.Conn interface. The read and write operations are
// overloaded to check that only cells are sent between agents in the mixnet
// protocol.
type Conn struct {
	net.Conn
}

// Read a cell from the channel. If len(msg) != CellBytes, return an error.
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

// Write a cell to the channel. If the len(cell) != CellBytes, return an error.
func (c *Conn) Write(msg []byte) (n int, err error) {
	if len(msg) != CellBytes {
		return 0, errCellLength
	}
	n, err = c.Conn.Write(msg)
	if err != nil {
		return n, err
	}
	return n, nil
}

// Serialize and pad a directive to the length of a cell and send it to the
// router. A directive is signaled to the receiver by the first byte of the
// cell. The next 8 bytes encodes the length of of the serialized protocol
// buffer. If the buffer doesn't fit in a cell, then throw an error.
func SendDirective(c net.Conn, d *Directive) (int, error) {
	db, err := proto.Marshal(d)
	if err != nil {
		return 0, err
	}
	dirBytes := len(db)

	// Throw an error if encoded Directive doesn't fit into a cell.
	if dirBytes+9 > CellBytes {
		return 0, errCellLength
	}

	cell := make([]byte, CellBytes)
	cell[0] = dirCell
	n := binary.PutUvarint(cell[1:], uint64(dirBytes))
	copy(cell[1+n:], db)

	return c.Write(cell)
}

// Write zeros to each byte of a cell.
func zeroCell(cell []byte) {
	for i := 0; i < CellBytes; i++ {
		cell[i] = 0
	}
}
