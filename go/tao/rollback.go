// Copyright (c) 2016, Google Inc. All rights reserved.
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

package tao

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"	// REMOVE
	"io/ioutil"
	"log"

	"github.com/golang/protobuf/proto"
)

func Protect(keys []byte, in []byte) ([]byte, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]byte, len(in), len(in))
	iv := make([]byte, 16, 16)
	_, err := rand.Read(iv[0:16])
	if err != nil {
		return nil, errors.New("Protect: Can't generate iv")
	}
	encKey := keys[0:16]
	macKey := keys[16:32]
	crypter, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, errors.New("Protect: Can't make crypter")
	}
	ctr := cipher.NewCTR(crypter, iv)
	ctr.XORKeyStream(out, in)

	hm := hmac.New(sha256.New, macKey)
	hm.Write(append(iv, out...))
	calculatedHmac := hm.Sum(nil)
	return append(calculatedHmac, append(iv, out...)...), nil
}

func Unprotect(keys []byte, in []byte) ([]byte, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]byte, len(in)-48, len(in)-48)
	var iv []byte
	iv = in[32:48]
	encKey := keys[0:16]
	macKey := keys[16:32]
	crypter, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, errors.New("Unprotect: Can't make crypter")
	}
	ctr := cipher.NewCTR(crypter, iv)
	ctr.XORKeyStream(out, in[48:])

	hm := hmac.New(sha256.New, macKey)
	hm.Write(in[32:])
	calculatedHmac := hm.Sum(nil)
	if bytes.Compare(calculatedHmac, in[0:32]) != 0 {
		return nil, errors.New("Unprotect: Bad mac")
	}
	return out, nil
}

// Read the counter table.
func ReadRollbackTable(fileName string, tableKey []byte) *RollbackCounterTable {
	blob, err := ioutil.ReadFile(fileName)
	if blob == nil || err != nil {
		// In either case we need a new table.
		return new(RollbackCounterTable)
	}

	// Decrypt and deserialize table.
	b, err := Unprotect(tableKey, blob)
	if err != nil {
		log.Printf("ReadRollbackTable: Unprotect failed %s", err)
		return nil
	}

	var t RollbackCounterTable
	err = proto.Unmarshal(b, &t)
	if err != nil {
		log.Printf("ReadRollbackTable: Unmarshal failed %s", err)
		return nil
	}
	return &t
}

// Write the counter table.
func WriteRollbackTable(rollBackTable *RollbackCounterTable, fileName string, tableKey []byte) bool {

	// Serialize and encrypt rollback table.
	blob, err := proto.Marshal(rollBackTable)
	if err != nil {
		log.Printf("WriteRollbackTable: Marshal failed\n")
		return false
	}
	b, err := Protect(tableKey, blob)
	if err != nil {
		log.Printf("WriteRollbackTable: Protect failed\n")
		return false
	}
	err = ioutil.WriteFile(fileName, b, 0644)
	if err != nil {
		log.Printf("WriteRollbackTable: WriteFile failed\n")
		return false
	}
	return true
}

func (e *RollbackEntry) PrintRollbackEntry() {
	if e.HostedProgramName == nil {
		fmt.Printf("HostedProgramName: empty, ")
	} else {
		fmt.Printf("HostedProgramName: %s, ", *e.HostedProgramName)
	}
	if  e.EntryLabel == nil {
		fmt.Printf("EntryLabel: empty, ")
	} else {
		fmt.Printf("EntryLabel: %s, ", *e.EntryLabel)
	}
	if  e.Counter == nil {
		fmt.Printf("Counter: empty\n")
	} else {
		fmt.Printf("Counter: %d\n", *e.Counter)
	}
}

func PrintSealedData(d *RollbackSealedData) {
	if d.Entry == nil {
		fmt.Printf("Rollback entry empty\n")
	} else {
		d.Entry.PrintRollbackEntry()
	}
	if d.ProtectedData == nil {
		fmt.Printf("Protected data: empty\n")
	} else {
		fmt.Printf("Protected data: %x\n", d.ProtectedData)
	}
}

func (t *RollbackCounterTable) PrintRollbackTable() {
	if t == nil {
		fmt.Printf("No rollback table\n")
		return
	}
	fmt.Printf("Rollback table %d entries\n", len(t.Entries)) //REMOVE
	for i := 0; i < len(t.Entries); i++ {
		t.Entries[i].PrintRollbackEntry()
	}
}

func (t *RollbackCounterTable) SaveHostRollbackTableWithNewKeys(lh *LinuxHost, child *LinuxHostChild,
		sealedKeyFileName string, tableFileName string) bool {
	fmt.Printf("SaveHostRollbackTableWithNewKeys %s %s\n", sealedKeyFileName, tableFileName) //REMOVE
	
	// Generate new rollback table sealing keys
	var newKeys [32]byte
	rand.Read(newKeys[0:32])

	b, err := lh.Host.RollbackProtectedSeal("Table_secret", newKeys[0:32], "self")
	if err != nil {
		log.Printf("SaveHostRollbackTable: Can't do RollbackProtectedSeal\n")
		return false
	}
	err = ioutil.WriteFile(sealedKeyFileName, b, 0644)
	if err != nil {
		log.Printf("SaveHostRollbackTable: Can't write sealedKeyFile\n")
		return false
	}

	// Save table.
	if !WriteRollbackTable(t, tableFileName, newKeys[0:32]) {
		log.Printf("WriteRollbackTable failed\n")
		return false
	}

	return true
}

// Lookup Rollback entry for programName, entryName).
func (t *RollbackCounterTable) LookupRollbackEntry(programName string, entryName string) *RollbackEntry {
	for i := 0; i < len(t.Entries) ; i++ {
		if t.Entries[i].HostedProgramName != nil && *t.Entries[i].HostedProgramName == programName &&
				t.Entries[i].EntryLabel != nil && *t.Entries[i].EntryLabel == entryName {
			return t.Entries[i]
		}
	}
	return nil
}

// Update Rollback entry for programName, entryName).
func (t *RollbackCounterTable) UpdateRollbackEntry(programName string, entryName string,
		 c *int64) *RollbackEntry {
	ent := t.LookupRollbackEntry(programName, entryName)
	if ent == nil {
		ent = new(RollbackEntry)
		ent.HostedProgramName = &programName
		ent.EntryLabel = &entryName
		zero := int64(0)
		ent.Counter = &zero
		t.Entries = append(t.Entries, ent)
	}
	if c != nil {
		ent.Counter = c
	}
	return ent
}

