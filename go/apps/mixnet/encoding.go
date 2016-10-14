// Copyright (c) 2016, Google Inc. All rights reserved.
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

	"github.com/golang/protobuf/proto"
)

// GetID returns the cell (circuit) ID.
func getID(cell []byte) uint64 {
	id := binary.LittleEndian.Uint64(cell[ID:])
	return id
}

// Transform a directive into a cell, encoding its length and padding it to the
// length of a cell.
func marshalDirective(id uint64, d *Directive) ([]byte, error) {
	db, err := proto.Marshal(d)
	if err != nil {
		return nil, err
	}
	dirBytes := uint64(len(db))

	cell := make([]byte, CellBytes)
	binary.LittleEndian.PutUint64(cell[ID:], id)

	cell[TYPE] = dirCell
	binary.LittleEndian.PutUint64(cell[BODY:], dirBytes)

	// Throw an error if encoded Directive doesn't fit into a cell.
	if dirBytes+LEN_SIZE+1 > CellBytes {
		return nil, errCellLength
	}
	copy(cell[BODY+LEN_SIZE:], db)

	return cell, nil
}

// Parse a directive from a cell.
func unmarshalDirective(cell []byte, d *Directive) error {
	if cell[TYPE] != dirCell {
		return errCellType
	}

	dirBytes := binary.LittleEndian.Uint64(cell[BODY:])
	if err := proto.Unmarshal(cell[BODY+LEN_SIZE:BODY+LEN_SIZE+int(dirBytes)], d); err != nil {
		return err
	}

	return nil
}
