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
	// "bytes"
	// "crypto/rand"
	//"crypto/x509"
	"errors"
	// "io/ioutil"
	"log"
	// "os"

	"code.google.com/p/goprotobuf/proto"

	// tao "github.com/jlmucb/cloudproxy/tao"
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
	Counter            int64
	// TODO: change magic allocation sizes
	NameandHashArray [100]NameandHash
}

type RollbackMaster struct {
	Initialized bool
	// TODO: fix magic length
	ProgramInfo [100]RollbackProgramInfo
}

func (r *RollbackMaster) FindRollbackProgramTable(programName string) (pi *RollbackProgramInfo) {
	for _, pi := range r.ProgramInfo {
		if pi.ProgramName == programName {
			return &pi
		}
	}
	return nil
}

func (r *RollbackMaster) AddRollbackProgramTable(programName string) *RollbackProgramInfo {
	pi := r.FindRollbackProgramTable(programName)
	if pi != nil {
		return pi
	}
	// r.ProgramInfo[0 : len(r.ProgramInfo)+1]
	pi = &r.ProgramInfo[len(r.ProgramInfo)-1]
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

func (pi *RollbackProgramInfo) FindRollbackHashEntry(itemName string) (hi *NameandHash) {
	for _, hi := range pi.NameandHashArray {
		if hi.ItemName == itemName {
			return &hi
		}
	}
	return nil
}

func (pi *RollbackProgramInfo) AddHashEntry(itemName string, hash []byte) *NameandHash {
	return nil
}

func (pi *RollbackProgramInfo) InitRollbackProgramInfo(subjectprogramName string) bool {
	pi.ProgramName = subjectprogramName
	pi.Counter = 0
	return true
}

func (r *RollbackMaster) InitRollbackMaster(masterprogramName string) bool {

	// read master
	// decrypt
	// update

	// read hash table
	// decrypt
	// update
	return false
}

func (r *RollbackMaster) SetRollbackCounter(ms *util.MessageStream, programName string, counter int64) bool {
	pi := r.FindRollbackProgramTable(programName)
	if pi == nil {
		log.Printf("SetRollbackCounter: program has no program info table")
		SendResponse(ms, "failed", "Rollback doesn't exist", 0)
		return false
	}
	if pi.Counter > counter {
		log.Printf("SetRollbackCounter: can't set counter backwards")
		SendResponse(ms, "failed", "Rollback counter can't decrease", 0)
		return false
	}
	pi.Counter = counter
	SendResponse(ms, "succeeded", "", 0)
	return true
}

func (r *RollbackMaster) SetRollbackResourceHash(ms *util.MessageStream, programName string, itemName string) bool {
	pi := r.FindRollbackProgramTable(programName)
	if pi == nil {
		log.Printf("SetRollbackResourceHash: program has no program info table")
		SendResponse(ms, "failed", "Rollback doesn't exist", 0)
		return false
	}
	// get hash
	hash, err := GetProtocolMessage(ms)
	if err != nil {
		log.Printf("SetRollbackResourceHash: program has no program info table")
		SendResponse(ms, "failed", "Rollback doesn't exist", 0)
		return false
	}
	hi := pi.FindRollbackHashEntry(itemName)
	if hi == nil {
		hi = pi.AddHashEntry(itemName, hash)
		if hi == nil {
			log.Printf("SetRollbackResourceHash: program has no program info table")
			SendResponse(ms, "failed", "can't insert entry", 0)
			return false
		}
	} else {
		hi.Hash = hash
	}
	SendResponse(ms, "succeeded", "", 0)
	return true
}

func (r *RollbackMaster) GetRollbackHashedVerifier(ms *util.MessageStream, programName string, itemName string) bool {
	pi := r.FindRollbackProgramTable(programName)
	if pi == nil {
		log.Printf("SetRollbackResourceHash: program has no program info table")
		SendResponse(ms, "failed", "Rollback doesn't exist", 0)
		return false
	}
	hi := pi.FindRollbackHashEntry(itemName)
	if hi == nil {
		log.Printf("SetRollbackResourceHash: program has no program info table")
		SendResponse(ms, "failed", "can't insert entry", 0)
		return false
	}
	hash := hi.Hash
	SendResponse(ms, "succeeded", "", 0)
	SendProtocolMessage(ms, len(hash), hash)
	return true
}

// Update hash for resouce named resource
func setRollbackCounter(ms *util.MessageStream, counter int64) bool {
	SendCounterRequest(ms, counter)
	status, _, _, err := GetResponse(ms)
	if status == nil || *status != "succeeded" || err != nil {
		return false
	}
	return true
}

// Update hash for resouce named resource
func setResourceHashRequest(ms *util.MessageStream, clientProgramName string, item string, hash []byte) bool {
	action := "setrollbackhash"
	SendRequest(ms, nil, &action, nil, nil)
	status, _, _, err := GetResponse(ms)
	if status == nil || *status != "succeeded" || err != nil {
		return false
	}
	err = SendProtocolMessage(ms, len(hash), hash)
	return false
}

// Update hash for resouce named resource
func getRollbackHashedVerifierRequest(ms *util.MessageStream, clientProgramName string, item string) (bool, []byte) {
	action := "getrollbackcounter"
	SendRequest(ms, nil, &action, nil, nil)
	hash, err := GetProtocolMessage(ms)
	status, _, _, err := GetResponse(ms)
	if status == nil || *status != "succeeded" || err != nil {
		return false, nil
	}
	return true, hash
}

// First return value is terminate flag
func (r *RollbackMaster) HandleServiceRequest(ms *util.MessageStream, programPolicyObject ProgramPolicy, clientProgramName string, request []byte) (bool, error) {
	log.Printf("rollbackhandler: HandleServiceRequest\n")

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
	case "setrollbackhash":
		if fpMessage.ResourceName == nil {
			log.Printf("HandleServiceRequest: no resource name in setrollbackhash message")
			SendResponse(ms, "failed", "no counter", 0)
		}
		_ = r.SetRollbackResourceHash(ms, clientProgramName, *fpMessage.ResourceName)
		return false, nil
	case "getrollbackcounter":
		if fpMessage.ResourceName == nil {
			log.Printf("HandleServiceRequest: no resource name in setrollbackhash message")
			SendResponse(ms, "failed", "no counter", 0)
		}
		r.GetRollbackHashedVerifier(ms, clientProgramName, *fpMessage.ResourceName)
		return false, nil
	default:
		SendResponse(ms, "failed", "", 0)
		return false, errors.New("unsupported action")
	}
}
