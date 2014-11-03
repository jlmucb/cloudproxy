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

func (r *RollbackMaster) AddRollbackProgramTable(programName string) (pi *RollbackProgramInfo) {
	return nil
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

func (pi *RollbackProgramInfo) AddHashEntry(itemName string, hash string) *NameandHash {
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

func (r *RollbackMaster) SetRollbackCounter(programName string, counter int64) bool {
	return false
}

func (r *RollbackMaster) SetRollbackResourceHash(programName string, resourceName string, hash string) bool {
	return false
}

func (r *RollbackMaster) GetRollbackHashedVerifier(programName string, resourceName string) bool {
	return false
}

// Update hash for resouce named resource
func setresourcehashRequest(ms *util.MessageStream, resource string, hash string) bool {
	return false
}

// Gets success/fail.

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
		return false, nil
	case "setrollbackhash":
		return false, nil
	case "getrollbackcounter":
		return false, nil
	default:
		SendResponse(ms, "failed", "", 0)
		return false, errors.New("unsupported action")
	}
}
