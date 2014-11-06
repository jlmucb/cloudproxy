// Copyright (c) 2014, Google Corporation.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
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
	"errors"
	"log"

	"code.google.com/p/goprotobuf/proto"

	"github.com/jlmucb/cloudproxy/util"
)

type NameandHash struct {
	ItemName string
	Hash     []byte
}

type RollbackProgramInfo struct {
	MasterInfoSaveFile string
	HashSaveFile       string
	ProgramName        string
	MonotonicCounter   int64
	Initialized        bool
	NameandHashArray   []NameandHash
}

type RollbackMaster struct {
	ProgramName string
	Initialized bool
	ProgramInfo []RollbackProgramInfo
}

func (r *RollbackMaster) FindRollbackProgramTable(programName string) *RollbackProgramInfo {
	for i := range r.ProgramInfo {
		if r.ProgramInfo[i].ProgramName == programName {
			return &r.ProgramInfo[i]
		}
	}
	return nil
}

func (r *RollbackMaster) AddRollbackProgramTable(programName string) *RollbackProgramInfo {
	log.Printf("AddRollbackProgramTable: %s\n", programName)
	pi := r.FindRollbackProgramTable(programName)
	if pi != nil {
		return pi
	}
	if len(r.ProgramInfo) >= cap(r.ProgramInfo) {
		t := make([]RollbackProgramInfo, 2*cap(r.ProgramInfo))
		copy(t, r.ProgramInfo)
		r.ProgramInfo = t
	}
	r.ProgramInfo = r.ProgramInfo[0 : len(r.ProgramInfo)+1]
	log.Printf("len(r.ProgramInfo)= %d, cap(r.ProgramInfo)= %d\n", len(r.ProgramInfo), cap(r.ProgramInfo))
	pi = &r.ProgramInfo[len(r.ProgramInfo)-1]
	pi.ProgramName = programName
	pi.MonotonicCounter = 3
	pi.NameandHashArray = make([]NameandHash, 100)
	pi.NameandHashArray = pi.NameandHashArray[0:0]
	log.Printf("len(pi.pi.NameandHashArray)= %d, cap(pi.pi.NameandHashArray)= %d\n", len(pi.NameandHashArray), cap(pi.NameandHashArray))
	pi.Initialized = true
	return pi
}

func (r *RollbackMaster) ReadMasterRollbackInfo(masterFile string, hashFile string) bool {
	return false
}

func (r *RollbackMaster) SaveMasterRollbackInfo(masterFile string, hashFile string) bool {
	return false
}

func (pi *RollbackProgramInfo) ReadProgramRollbackInfo(programName string, masterFile string, hashFile string) bool {
	return false
}

func (pi *RollbackProgramInfo) SaveProgramRollbackInfo(programName string, masterFile string, hashFile string) bool {
	return false
}

func (pi *RollbackProgramInfo) FindRollbackHashEntry(itemName string) *NameandHash {
	for i := range pi.NameandHashArray {
		log.Printf("FindRollbackHashEntry %s %s\n", itemName, pi.NameandHashArray[i].ItemName)
		if pi.NameandHashArray[i].ItemName == itemName {
			return &pi.NameandHashArray[i]
		}
	}
	return nil
}

func (pi *RollbackProgramInfo) AddHashEntry(itemName string, hash []byte) *NameandHash {
	log.Printf("AddHashEntry %s\n", itemName)
	he := pi.FindRollbackHashEntry(itemName)
	if he != nil {
		he.Hash = hash
		return he
	}
	if len(pi.NameandHashArray) >= cap(pi.NameandHashArray) {
		t := make([]NameandHash, 2*cap(pi.NameandHashArray))
		copy(t, pi.NameandHashArray)
		pi.NameandHashArray = t
	}
	pi.NameandHashArray = pi.NameandHashArray[0 : len(pi.NameandHashArray)+1]
	he = &pi.NameandHashArray[len(pi.NameandHashArray)-1]
	he.ItemName = itemName
	he.Hash = hash
	log.Printf("item: %s, hash %x\n", itemName, hash)
	return he
}

func (r *RollbackMaster) InitRollbackMaster(masterprogramName string) bool {
	log.Printf("InitRollbackMaster\n")
	r.Initialized = true
	r.ProgramName = masterprogramName
	r.ProgramInfo = make([]RollbackProgramInfo, 100)
	r.ProgramInfo = r.ProgramInfo[0:0]
	log.Printf("len(r.ProgramInfo)= %d, cap(r.ProgramInfo)= %d\n", len(r.ProgramInfo), cap(r.ProgramInfo))
	// read master
	// decrypt
	// update

	// read hash table
	// decrypt
	// update
	return true
}

func (r *RollbackMaster) SetRollbackCounter(ms *util.MessageStream, programName string, counter int64) bool {
	pi := r.FindRollbackProgramTable(programName)
	if pi == nil {
		log.Printf("SetRollbackCounter: program has no program info table 1")
		SendResponse(ms, "failed", "Rollback doesn't exist", 0)
		return false
	}
	if pi.MonotonicCounter > counter {
		log.Printf("SetRollbackCounter: can't set counter backwards")
		SendResponse(ms, "failed", "Rollback counter can't decrease", 0)
		return false
	}
	pi.MonotonicCounter = counter
	log.Printf("SetRollbackCounter (%s) table counter: %d\n", pi.ProgramName, pi.MonotonicCounter)
	SendResponse(ms, "succeeded", "", 0)
	return true
}

func (r *RollbackMaster) SetRollbackResourceHash(ms *util.MessageStream, programName string, itemName string) bool {
	pi := r.FindRollbackProgramTable(programName)
	if pi == nil {
		log.Printf("SetRollbackResourceHash: program has no program info table 2")
		SendResponse(ms, "failed", "Rollback doesn't exist", 0)
		return false
	}
	SendResponse(ms, "succeeded", "", 0)
	// get hash
	hash, err := GetProtocolMessage(ms)
	if err != nil {
		log.Printf("SetRollbackResourceHash: GetProtocolMessage failed\n")
		SendResponse(ms, "failed", "Rollback doesn't exist", 0)
		return false
	}
	hi := pi.FindRollbackHashEntry(itemName)
	if hi == nil {
		hi = pi.AddHashEntry(itemName, hash)
		if hi == nil {
			log.Printf("SetRollbackResourceHash: no hash entry\n")
			SendResponse(ms, "failed", "can't insert entry", 0)
			return false
		}
	} else {
		log.Printf("SetRollbackResourceHash, found %s entry\n", hi.ItemName)
		hi.Hash = hash
	}
	return true
}

func (r *RollbackMaster) GetRollbackCounter(ms *util.MessageStream, programName string) bool {
	pi := r.FindRollbackProgramTable(programName)
	if pi == nil {
		log.Printf("GetRollbackCounter: program has no program info table\n")
		SendResponse(ms, "failed", "Rollback doesn't exist", 0)
		return false
	}
	log.Printf("GetRollbackCounter(%s), counter: %d\n", pi.ProgramName, pi.MonotonicCounter)
	SendCounterResponse(ms, "succeeded", "", pi.MonotonicCounter)
	return true
}

func (r *RollbackMaster) GetRollbackHashedVerifier(ms *util.MessageStream, programName string, itemName string) bool {
	log.Printf("GetRollbackHashedVerifier\n")
	pi := r.FindRollbackProgramTable(programName)
	if pi == nil {
		log.Printf("GetRollbackHashedVerifier: program has no program info table")
		SendResponse(ms, "failed", "Rollback doesn't exist", 0)
		return false
	}
	hi := pi.FindRollbackHashEntry(itemName)
	if hi == nil {
		log.Printf("GetRollbackResourceHash: program has no hash entry for %s\n", itemName)
		SendResponse(ms, "failed", "can't insert entry", 0)
		return false
	}
	// now has the epoch and the hash and return thatkk
	sha256Hash := sha256.New()
	b := make([]byte, 8)
	binary.PutVarint(b, pi.MonotonicCounter)
	sha256Hash.Write(b)
	sha256Hash.Write(hi.Hash)
	sha256Hash.Write(b)
	hash := sha256Hash.Sum(nil)
	SendResponse(ms, "succeeded", "", 0)
	SendProtocolMessage(ms, len(hash), hash)
	return true
}

// Update hash for resouce named resource
func ClientSetRollbackCounter(ms *util.MessageStream, counter int64) bool {
	SendCounterRequest(ms, counter)
	status, _, _, err := GetResponse(ms)
	if err != nil || status == nil || *status != "succeeded" {
		return false
	}
	return true
}

func ClientSetResourceHashRequest(ms *util.MessageStream, clientProgramName string, item string, hash []byte) bool {
	log.Printf("ClientSetResourceHashRequest %s, %s\n", clientProgramName, item)
	action := "setrollbackhash"
	SendRequest(ms, nil, &action, &item, nil)
	status, _, _, err := GetResponse(ms)
	if err != nil || status == nil || *status != "succeeded" {
		log.Printf("ClientSetResourceHashRequest failed\n")
		return false
	}
	err = SendProtocolMessage(ms, len(hash), hash)
	return true
}

func ClientGetRollbackCounter(ms *util.MessageStream, clientProgramName string) (bool, int64) {
	log.Printf("ClientGetRollbackCounter%s, %s\n", clientProgramName)
	action := "getrollbackcounter"
	SendRequest(ms, &clientProgramName, &action, nil, nil)
	status, _, counter, err := GetCounterResponse(ms)
	if err != nil || status == nil || *status != "succeeded" || counter == nil {
		if err != nil {
			log.Printf("ClientGetRollbackCounter, err is not nil\n")
		}
		if status == nil {
			log.Printf("ClientGetRollbackCounter, status is nil\n")
		}
		log.Printf("ClientGetRollbackCounter: %s\n", *status)
		if counter == nil {
			log.Printf("ClientGetRollbackCounter, counter is nil\n")
		}
		return false, 0
	}
	return true, *counter
}

func ClientGetRollbackHashedVerifierRequest(ms *util.MessageStream, clientProgramName string, item string) (bool, []byte) {
	log.Printf("ClientGetRollbackHashedVerifierRequest: %s, %s\n", clientProgramName, item)
	action := "getrollbackcounterverifier"
	SendRequest(ms, nil, &action, &item, nil)
	status, _, _, err := GetResponse(ms)
	if status == nil || *status != "succeeded" || err != nil {
		return false, nil
	}
	hash, err := GetProtocolMessage(ms)
	return true, hash
}

// First return value is terminate flag
func (r *RollbackMaster) HandleServiceRequest(ms *util.MessageStream, programPolicyObject *ProgramPolicy, clientProgramName string, request []byte) (bool, error) {
	log.Printf("rollbackhandler: HandleServiceRequest for %s\n", clientProgramName)

	fpMessage := new(FPMessage)
	err := proto.Unmarshal(request, fpMessage)
	if err != nil {
		return false, errors.New("HandleService can't unmarshal request")
	}
	if fpMessage.MessageType == nil {
		return false, errors.New("HandleService: no message type")
	}
	switch MessageType(*fpMessage.MessageType) {
	case MessageType_REQUEST:
	default:
		return false, errors.New("HandleService does not get MessageType_REQUEST")
	}
	action := fpMessage.ActionName
	if action == nil {
		SendResponse(ms, "failed", "", 0)
		return false, errors.New("no action")
	}

	switch *action {
	case "setrollbackcounter":
		if fpMessage.MonotonicCounter == nil {
			log.Printf("HandleServiceRequest: no counter in setrollbackcounter message")
			SendResponse(ms, "failed", "no counter", 0)
		}
		_ = r.SetRollbackCounter(ms, clientProgramName, *fpMessage.MonotonicCounter)
		return false, nil
	case "getrollbackcounter":
		_ = r.GetRollbackCounter(ms, clientProgramName)
		return false, nil
	case "setrollbackhash":
		if fpMessage.ResourceName == nil {
			log.Printf("HandleServiceRequest: no resource name in setrollbackhash message")
			SendResponse(ms, "failed", "no counter", 0)
		}
		_ = r.SetRollbackResourceHash(ms, clientProgramName, *fpMessage.ResourceName)
		return false, nil
	case "getrollbackcounterverifier":
		if fpMessage.ResourceName == nil {
			log.Printf("HandleServiceRequest: no resource name in getrollbackcounterverifier message")
			SendResponse(ms, "failed", "no counter", 0)
		}
		r.GetRollbackHashedVerifier(ms, clientProgramName, *fpMessage.ResourceName)
		return false, nil
	default:
		SendResponse(ms, "failed", "", 0)
		return false, errors.New("unsupported action")
	}
}
