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
	"net"
	"sync"
	"time"
)

// Conn implements the net.Conn interface. The read and write operations are
// overloaded to check that only cells are sent between entities in the mixnet
// protocol.
type Conn struct {
	net.Conn
	id        uint32
	timeout   time.Duration // timeout on read/write.
	circuits  map[uint64]*Circuit
	cLock     *sync.RWMutex
	withProxy bool
}

// Read a cell from the channel. If len(msg) != CellBytes, return an error.
func (c *Conn) Read(msg []byte) (n int, err error) {
	c.Conn.SetDeadline(time.Now().Add(c.timeout))
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
	c.Conn.SetDeadline(time.Now().Add(c.timeout))
	if len(msg) != CellBytes {
		return 0, errCellLength
	}
	n, err = c.Conn.Write(msg)
	if err != nil {
		return n, err
	}
	return n, nil
}

func (c *Conn) Member(id uint64) bool {
	c.cLock.RLock()
	_, ok := c.circuits[id]
	c.cLock.RUnlock()
	return ok
}

func (c *Conn) GetCircuit(id uint64) *Circuit {
	c.cLock.RLock()
	defer c.cLock.RUnlock()
	return c.circuits[id]
}

func (c *Conn) AddCircuit(circuit *Circuit) {
	c.cLock.Lock()
	defer c.cLock.Unlock()
	c.circuits[circuit.id] = circuit
}

func (c *Conn) DeleteCircuit(circuit *Circuit) bool {
	c.cLock.Lock()
	defer c.cLock.Unlock()
	close(circuit.cells)
	delete(c.circuits, circuit.id)
	return len(c.circuits) == 0
}

func (c *Conn) Empty() bool {
	c.cLock.RLock()
	defer c.cLock.RUnlock()
	return len(c.circuits) == 0
}
