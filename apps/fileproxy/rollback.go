// Copyright (c) 2014, Google, Inc.,  All rights reserved.
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
//
// File: rollbackhandler.go

package fileproxy

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"

	"code.google.com/p/goprotobuf/proto"

	"github.com/jlmucb/cloudproxy/util"
)

// A RollbackProgram stores the rollback information for a given program.
type RollbackProgram struct {
	MasterInfoSaveFile string
	HashSaveFile       string
	Name               string
	MonotonicCounter   uint64
	Hashes             map[string][]byte
}

// A RollbackMaster stores information about the rollback state of all programs
// that use the RollbackMaster.
type RollbackMaster struct {
	Name     string
	Programs map[string]*RollbackProgram
}

// FindRollbackProgram finds a given RollbackProgram by name
func (r *RollbackMaster) FindRollbackProgram(name string) *RollbackProgram {
	return r.Programs[name]
}

// AddRollbackProgram inserts a rollback program with a given name into the
// table. If there is already a program with this name, then it returns the
// program that already has that name.
func (r *RollbackMaster) AddRollbackProgram(name string) *RollbackProgram {
	pi := r.FindRollbackProgram(name)
	if pi != nil {
		return pi
	}

	pi = &RollbackProgram{
		Name:             name,
		MonotonicCounter: 0,
		Hashes:           make(map[string][]byte),
	}
	r.Programs[name] = pi
	return pi
}

// FindRollbackHashEntry looks up the hash for a given item name in a rollback
// program. Note that it returns the default value of a slice (nil) if the name
// doesn't exist.
func (pi *RollbackProgram) FindRollbackHashEntry(name string) []byte {
	return pi.Hashes[name]
}

// AddRollbackHashEntry adds a given name/hash pair to the map and updates the
// hash if this name already exists.
func (pi *RollbackProgram) AddRollbackHashEntry(name string, newHash []byte) error {
	pi.Hashes[name] = newHash
	return nil
}

// NewRollbackMaster creates a new RollbackMaster with the given name.
func NewRollbackMaster(name string) *RollbackMaster {
	r := &RollbackMaster{
		Name:     name,
		Programs: make(map[string]*RollbackProgram),
	}
	return r
}

// EncodeCounter takes in a counter and returns a slice that exactly encodes a
// varint representation of this counter.
func EncodeCounter(counter uint64) []byte {
	b := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(b, counter)
	return b[:n]
}

// decodeCounter takes in a slice and attempts to decode it as a uint64 value.
func decodeCounter(b []byte) (uint64, error) {
	i, n := binary.Uvarint(b)
	if n <= 0 {
		return 0, fmt.Errorf("couldn't decode the counter")
	}
	return i, nil
}

// SetRollbackCounter sets the monotonic counter for a given program to a higher
// value. It returns an error if the program doesn't exist or if the new value
// of the counter is less than the current value of the counter.
func (r *RollbackMaster) SetCounter(ms *util.MessageStream, name string, counter uint64) error {
	emptyData := make([]byte, 0)
	rr := &RollbackResponse{
		Type: RollbackMessageType_ERROR.Enum(),
		Data: emptyData,
	}

	p := r.FindRollbackProgram(name)
	if p == nil {
		if _, err := ms.WriteMessage(rr); err != nil {
			return err
		}
		return fmt.Errorf("couldn't find a rollback program with name %s", name)
	}

	if p.MonotonicCounter > counter {
		if _, err := ms.WriteMessage(rr); err != nil {
			return err
		}
		return fmt.Errorf("couldn't write a smaller counter value %d for %s", counter, name)
	}
	// TODO(tmroeder): this needs synchronization for any real application.
	p.MonotonicCounter = counter
	rr.Type = RollbackMessageType_SET_COUNTER.Enum()
	rr.Data = EncodeCounter(p.MonotonicCounter)
	if _, err := ms.WriteMessage(rr); err != nil {
		return err
	}

	return nil
}

// SetHash implements RollbackMessageType_SET_HASH by setting the value of the
// hash for a given item to a given hash value.
func (r *RollbackMaster) SetHash(ms *util.MessageStream, name string, item string, h []byte) error {
	emptyData := make([]byte, 0)
	rr := &RollbackResponse{
		Type: RollbackMessageType_ERROR.Enum(),
		Data: emptyData,
	}

	p := r.FindRollbackProgram(name)
	if p == nil {
		if _, err := ms.WriteMessage(rr); err != nil {
			return err
		}
		return fmt.Errorf("couldn't find a rollback program with name %s", name)
	}

	// Set the hash.
	if err := p.AddRollbackHashEntry(item, h); err != nil {
		if _, e := ms.WriteMessage(rr); e != nil {
			return e
		}
		return err
	}

	rh := &RollbackHash{
		Item: proto.String(item),
		Hash: h,
	}
	rhb, err := proto.Marshal(rh)
	if err != nil {
		if _, e := ms.WriteMessage(rr); e != nil {
			return e
		}
		return err
	}

	// TODO(tmroeder): Do you need to update the counter when you update the
	// hash?
	rr.Type = RollbackMessageType_SET_HASH.Enum()
	rr.Data = rhb
	_, err = ms.WriteMessage(rr)
	return err
}

// GetCounter implements RollbackMessageType_GET_COUNTER and returns the current
// value of a counter to the requestor.
func (r *RollbackMaster) GetCounter(ms *util.MessageStream, name string) error {
	emptyData := make([]byte, 0)
	rr := &RollbackResponse{
		Type: RollbackMessageType_ERROR.Enum(),
		Data: emptyData,
	}

	p := r.FindRollbackProgram(name)
	if p == nil {
		if _, err := ms.WriteMessage(rr); err != nil {
			return err
		}
		return fmt.Errorf("couldn't find a rollback program with name %s", name)
	}

	rr.Type = RollbackMessageType_GET_COUNTER.Enum()
	rr.Data = EncodeCounter(p.MonotonicCounter)
	_, err := ms.WriteMessage(rr)
	return err
}

// GetHashedVerifier gets a version of the hash for a given item along with the
// current monotonic counter.
func (r *RollbackMaster) GetHashedVerifier(ms *util.MessageStream, name string, item string) error {
	emptyData := make([]byte, 0)
	rr := &RollbackResponse{
		Type: RollbackMessageType_ERROR.Enum(),
		Data: emptyData,
	}

	p := r.FindRollbackProgram(name)
	if p == nil {
		if _, err := ms.WriteMessage(rr); err != nil {
			return err
		}
		return fmt.Errorf("couldn't find a rollback program with name %s", name)
	}

	h := p.FindRollbackHashEntry(item)
	if h == nil {
		if _, err := ms.WriteMessage(rr); err != nil {
			return err
		}
		return fmt.Errorf("couldn't find an item with name '%s' in program '%s'", item, name)
	}
	// Return SHA-256(Counter || Hash || Counter).
	// TODO(tmroeder): what is the justification for this protocol?
	sha256Hash := sha256.New()
	b := EncodeCounter(p.MonotonicCounter)
	sha256Hash.Write(b)
	sha256Hash.Write(h)
	sha256Hash.Write(b)
	hash := sha256Hash.Sum(nil)

	rr.Type = RollbackMessageType_GET_HASHED_VERIFIER.Enum()
	rr.Data = hash[:]
	_, err := ms.WriteMessage(rr)
	return err
}

// The following functions are used by clients to access a remote rollback
// server.

// checkResponse waits for a RollbackResponse and checks to make sure it's not
// an ERROR response from the server.
func checkResponse(ms *util.MessageStream) error {
	var rr RollbackResponse
	if err := ms.ReadMessage(&rr); err != nil {
		return err
	}
	if *rr.Type == RollbackMessageType_ERROR {
		return fmt.Errorf("couldn't set the counter on the remote server")
	}
	return nil
}

// SetCounter sets the remote counter for this program.
func SetCounter(ms *util.MessageStream, counter uint64) error {
	rm := &RollbackMessage{
		Type: RollbackMessageType_SET_COUNTER.Enum(),
		Data: EncodeCounter(counter),
	}
	if _, err := ms.WriteMessage(rm); err != nil {
		return err
	}

	// TODO(tmroeder): we currently ignore the value of the counter returned
	// by the server.
	return checkResponse(ms)
}

// SetHash sets the value of a hash for a given item for this program.
func SetHash(ms *util.MessageStream, item string, hash []byte) error {
	rh := &RollbackHash{
		Item: proto.String(item),
		Hash: hash,
	}
	rhb, err := proto.Marshal(rh)
	if err != nil {
		return err
	}
	rm := &RollbackMessage{
		Type: RollbackMessageType_SET_HASH.Enum(),
		Data: rhb,
	}
	if _, err := ms.WriteMessage(rm); err != nil {
		return err
	}

	return checkResponse(ms)
}

// GetCounter gets the current value of the monotonic counter for a given
// program name.
func GetCounter(ms *util.MessageStream) (uint64, error) {
	// The name of the program is managed by the rollback server, not the
	// client, so it doesn't need to be passed in the message.
	rm := &RollbackMessage{
		Type: RollbackMessageType_GET_COUNTER.Enum(),
		Data: make([]byte, 0),
	}
	if _, err := ms.WriteMessage(rm); err != nil {
		return 0, err
	}

	// We can't use checkResponse here since we need to get the value out of
	// the response to read the counter.
	var rr RollbackResponse
	if err := ms.ReadMessage(&rr); err != nil {
		return 0, err
	}
	if *rr.Type == RollbackMessageType_ERROR {
		return 0, fmt.Errorf("couldn't set the counter on the remote server")
	}

	return decodeCounter(rr.Data)
}

// GetHashedVerifier gets the hash of the counter and the item hash for a given
// item.
func GetHashedVerifier(ms *util.MessageStream, item string) ([]byte, error) {
	rm := &RollbackMessage{
		Type: RollbackMessageType_GET_HASHED_VERIFIER.Enum(),
		Data: []byte(item),
	}
	if _, err := ms.WriteMessage(rm); err != nil {
		return nil, err
	}

	// We can't use checkResponse here since we need to get the value out of
	// the response to read the hash.
	var rr RollbackResponse
	if err := ms.ReadMessage(&rr); err != nil {
		return nil, err
	}
	if *rr.Type == RollbackMessageType_ERROR {
		return nil, fmt.Errorf("couldn't set the counter on the remote server")
	}

	return rr.Data, nil
}

// RunMessageLoop handles incoming messages for the RollbackMaster and passes
// them to the appropriate functions.
func (m *RollbackMaster) RunMessageLoop(ms *util.MessageStream, programPolicy *ProgramPolicy, name string) error {
	for {
		var msg RollbackMessage
		if err := ms.ReadMessage(&msg); err != nil {
			return err
		}

		switch *msg.Type {
		case RollbackMessageType_SET_COUNTER:
			i, err := decodeCounter(msg.Data)
			if err != nil {
				log.Printf("failed to decode counter for SET_COUNTER: %s", err)
				continue
			}

			if err = m.SetCounter(ms, name, i); err != nil {
				log.Printf("failed to set the counter on the RollbackMaster: %s", err)
				continue
			}
		case RollbackMessageType_GET_COUNTER:
			if err := m.GetCounter(ms, name); err != nil {
				log.Printf("failed to get the counter for program %s", name)
				continue
			}
		case RollbackMessageType_SET_HASH:
			var rh RollbackHash
			if err := proto.Unmarshal(msg.Data, &rh); err != nil {
				log.Printf("failed to unmarshal the parameters for SET_HASH: %s", err)
				continue
			}
			if err := m.SetHash(ms, name, *rh.Item, rh.Hash); err != nil {
				log.Printf("failed to set the hash for item %s on program %s: %s", *rh.Item, name, err)
				continue
			}
		case RollbackMessageType_GET_HASHED_VERIFIER:
			if err := m.GetHashedVerifier(ms, name, string(msg.Data)); err != nil {
				log.Printf("failed to get the hashed verifier for program %s: %s", name, err)
				continue
			}
		default:
			log.Printf("unknown rollback message %d", *msg.Type)
		}
	}

	return nil
}
