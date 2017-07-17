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
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/golang/protobuf/proto"
)

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
		log.Printf("WriteRollbackTable: Protect failed " + err.Error() + "\n")
		return false
	}
	err = ioutil.WriteFile(fileName, b, 0644)
	if err != nil {
		log.Printf("WriteRollbackTable: WriteFile failed " + err.Error() + "\n")
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
	if e.EntryLabel == nil {
		fmt.Printf("EntryLabel: empty, ")
	} else {
		fmt.Printf("EntryLabel: %s, ", *e.EntryLabel)
	}
	if e.Counter == nil {
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
	for i := 0; i < len(t.Entries); i++ {
		t.Entries[i].PrintRollbackEntry()
	}
}

func (t *RollbackCounterTable) SaveHostRollbackTableWithNewKeys(lh *LinuxHost, child *LinuxHostChild,
	sealedKeyFileName string, tableFileName string) bool {
	// TODO(jlm): child argument not used, remove?
	// Generate new rollback table sealing keys
	keyType := CrypterTypeFromSuiteName(TaoCryptoSuite)
	if keyType == nil {
		return false
	}
	totalKeySize := CombinedKeySizeFromAlgorithmName(*keyType)
	if totalKeySize == nil {
		return false
	}
	newKeys := make([]byte, *totalKeySize, *totalKeySize)
	rand.Read(newKeys[0:*totalKeySize])

	b, err := lh.Host.RollbackProtectedSeal("Table_secret", newKeys[0:*totalKeySize], "self")
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
	if !WriteRollbackTable(t, tableFileName, newKeys[0:*totalKeySize]) {
		log.Printf("WriteRollbackTable failed\n")
		return false
	}

	return true
}

// Lookup Rollback entry for programName, entryName).
func (t *RollbackCounterTable) LookupRollbackEntry(programName string, entryName string) *RollbackEntry {
	for i := 0; i < len(t.Entries); i++ {
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
