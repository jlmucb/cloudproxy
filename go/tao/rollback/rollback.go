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

package rollback 

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/golang/protobuf/proto"
)

func ZeroBytes(buf []byte) {
	n := len(buf)
	for i := 0; i < n; i++ {
		buf[i] = 0
	}
}

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


// The following are dummy routines.  Implementations will be replaced when integrated.

// Fake host counter for testing.
var myCounter int64

// For testing only.
func SetFakeSealedHostKey(key []byte, fileName string) bool {
	e := new(RollbackSealedData)
	e.Entry = new(RollbackEntry)
	e.Entry.HostedProgramName = getHostedProgramName()
	secret := "Host_secret"
	e.Entry.EntryLabel = &secret
	c := hostCounter()
	e.Entry.Counter =  &c
	e.ProtectedData = key
	b := seal(*e)
	if b == nil {
		log.Printf("SetFakeSealedHostKey: seal failed\n")
		return false
	}
	err := ioutil.WriteFile(fileName, b, 0644)
	if err != nil {
		log.Printf("SetFakeSealedHostKey: can't write %s\n", fileName)
		return false
	}
	return true
}

// End of dummy routines.


// Replace with Host's seal for the HostedProgram.
func seal(entry RollbackSealedData) []byte {
	a, err := proto.Marshal(&entry)
	if err != nil {
		log.Printf("seal: Marshal fails\n")
		return nil 
	}
	return a 
}

// Replace with Host's unseal for the HostedProgram.
func unseal(data []byte) *RollbackSealedData {
	var a RollbackSealedData 
	err := proto.Unmarshal(data, &a)
	if err != nil {
		log.Printf("unseal: Unmarshal fails %s\n", err)
		return nil
	}
	return &a
}

// Seal Tpm blob.
func sealTpmBlob(entry RollbackSealedData) []byte {
	return nil
}

// Unseal Tpm blob.
func unsealTpmBlob(d []byte)  *RollbackSealedData {
	return nil
}

// Seal Tpm2 blob.
func sealTpm2Blob(entry RollbackSealedData) []byte {
	return nil
}

// Unseal Tpm2 blob.
func unsealTpm2Blob(d []byte)  *RollbackSealedData {
	return nil
}

// Replace with Host lookup of HostedProgramName.
func getHostedProgramName() *string {
	var name string
	name = "ProgramName"
	return &name
}

// Returns root type for this host.  nil for stacked host.
//	Options: tpm1.2, tpm2.0, key
func hostRootType() *string {
	return nil
}

// hostCounter
func hostCounter() int64 {
	return myCounter
}

// Bump TPM counter.
func BumpTpmHostCounter() int64 {
	return 1
}

// Bump TPM2 counter.
func BumpTpm2HostCounter() int64 {
	return 1
}

// Bump current host counter via call to Host's host or the tpm.
func BumpMyHostCounter() int64 {
	myCounter = myCounter + 1
	return myCounter
}

// Init TPM Counter
func InitTpmCounter() int64 {
	return myCounter
}

// Init TPM2 Counter
func InitTpm2Counter() int64 {
	return myCounter
}

// Get TPM Counter
func GetTpmCounter() int64 {
	return hostCounter()
}

// Get TPM2 Counter
func GetTpm2Counter() int64 {
	return hostCounter()
}

// Get current Host counter via call to Host's host or the tpm.
func GetMyHostCounter() int64 {
	return hostCounter()
}

// For testing only.
func SetHostCounter(c int64) int64 {
	myCounter = c
	return myCounter
}

// Replace these with host call to it's host for a Unseal
//	if this is a stacked tao.  For a root tao, this must call custom
//	functions to handle hardware based counter.
func unsealRollBackProtectedTableSealingKey(blob []byte) []byte {
	hostRoot := hostRootType()
	var b *RollbackSealedData
	var c int64
	if hostRoot == nil {
		c = hostCounter()
		b = unseal(blob)
		if b == nil {
			log.Printf("unsealRollBackProtectedTableSealingKey: unseal fails\n")
			return nil
		}
		/*
		if b == nil || b.Entry.Counter== nil || c != *b.Entry.Counter {
			log.Printf("unsealRollBackProtectedTableSealingKey: counter doesn't match\n")
			return nil
		}
		 */
	} else if *hostRoot == "tpm" {
		log.Printf("unsealRollBackProtectedTableSealingKey: doesn't support tpm counter yet\n")
		return nil
		if InitTpmCounter() < 0 {
			log.Printf("unsealRollBackProtectedTableSealingKey: can't init Tpm counter\n")
			return nil
		}
		c = GetTpmCounter()
		b = unsealTpmBlob(blob)
		// Check counter.
		if b == nil || b.Entry.Counter== nil || c != *b.Entry.Counter {
			log.Printf("unsealRollBackProtectedTableSealingKey: counter doesn't match\n")
			return nil
		}
	} else if *hostRoot == "tpm2" {
		log.Printf("unsealRollBackProtectedTableSealingKey: doesn't support tpm2 counter yet\n")
		return nil
		if InitTpm2Counter() < 0 {
			log.Printf("unsealRollBackProtectedTableSealingKey: can't init tpm2 counter\n")
			return nil
		}
		c = GetTpm2Counter()
		b = unsealTpm2Blob(blob)
		// Check counter.
		if b == nil || b.Entry.Counter== nil || c != *b.Entry.Counter {
			log.Printf("unsealRollBackProtectedTableSealingKey: counter doesn't match\n")
			return nil
		}
	} else {
		log.Printf("unsealRollBackProtectedTableSealingKey: bad host type\n")
		return nil
	}
	// Check the label
	if *b.Entry.EntryLabel != "Host_secret" {
		log.Printf("unsealRollBackProtectedTableSealingKey: entry label is wrong\n")
		return nil
	}
	return b.ProtectedData
}

// Replace these with host call to it's host for a RollBackBrotectedSeal.
//	if this is a stacked tao.  For a root tao, this must call custom
//	functions to handle hardware based counter.
func sealRollBackProtectedTableSealingKey(key []byte) []byte {

	hostRoot := hostRootType()
	e := new(RollbackSealedData)
	e.Entry = new(RollbackEntry)
	entryLabel := "Host_secret"
	e.Entry.HostedProgramName = getHostedProgramName()
	e.Entry.EntryLabel = &entryLabel
	e.ProtectedData = key

	if hostRoot == nil {
		BumpMyHostCounter()
		c := hostCounter()
		e.Entry.Counter = &c
		return seal(*e)
	} else if *hostRoot == "tpm" {
		log.Printf("sealRollBackProtectedTableSealingKey: doesn't support tpm counter yet\n")
		return nil
		if InitTpmCounter() < 0 {
			log.Printf("unsealRollBackProtectedTableSealingKey: can't init tpm counter\n")
			return nil
		}
		c := BumpTpmHostCounter()
		e.Entry.Counter = &c
		return sealTpmBlob(*e)
	} else if *hostRoot == "tpm2" {
		log.Printf("unsealRollBackProtectedTableSealingKey: doesn't support tpm2 counter yet\n")
		return nil
		if InitTpm2Counter() < 0 {
			log.Printf("unsealRollBackProtectedTableSealingKey: can't init tpm2 counter\n")
			return nil
		}
		c := BumpTpm2HostCounter()
		e.Entry.Counter = &c
		return sealTpm2Blob(*e)
	} else {
		log.Printf("sealRollBackProtectedTableSealingKey: bad host type\n")
		return nil
	}
}

// Read the counter table.
func ReadCounterTable(fileName string, tableKey []byte) *RollbackCounterTable {
	blob, err := ioutil.ReadFile(fileName)
	if blob == nil || err != nil {
		return new(RollbackCounterTable)
	}

	// Decrypt and deserialize table.
	b, err := Unprotect(tableKey, blob)
	if err != nil {
		log.Printf("ReadCounterTable: Unprotect failed\n")
		return nil
	}

	var t RollbackCounterTable
	err = proto.Unmarshal(b, &t)
	if err != nil {
		log.Printf("ReadCounterTable: Unmarshal failed\n")
		return nil
	}
	return &t 
}

// Write the counter table.
func WriteCounterTable(rollBackTable *RollbackCounterTable, fileName string, tableKey []byte) bool {

	// Serialize and encrypt rollback table.
	blob, err := proto.Marshal(rollBackTable)
	if err != nil {
		log.Printf("WriteCounterTable: Marshal failed\n")
		return false
	}
	b, err := Protect(tableKey, blob)
	if err != nil {
		log.Printf("WriteCounterTable: Protect failed\n")
		return false
	}
	err = ioutil.WriteFile(fileName, b, 0644)
	if err != nil {
		log.Printf("WriteCounterTable: WriteFile failed\n")
		return false
	}
	return true
}

func PrintEntry(e *RollbackEntry) {
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
		PrintEntry(d.Entry)
	}
	if d.ProtectedData == nil {
		fmt.Printf("Protected data: empty\n")
	} else {
		fmt.Printf("Protected data: %x\n", d.ProtectedData)
	}
}

func PrintTable(t *RollbackCounterTable) {
	if t == nil {
		fmt.Printf("No rollback table\n")
		return
	}
	fmt.Printf("Rollback table %d entries\n", len(t.Entries))
	for i := 0; i < len(t.Entries); i++ {
		PrintEntry(t.Entries[i])
	}
}

func SaveHostCounterTableWithNewKeys(sealedKeyFileName string, tableFileName string, t *RollbackCounterTable) bool {

	// Generate new rollback table sealing keys
	var newKeys [32]byte
	rand.Read(newKeys[0:32])

	// Save sealed rollback table sealing keys
	b := sealRollBackProtectedTableSealingKey(newKeys[0:32])
	if b == nil {
		log.Printf("SaveTableWithNewKeys: sealRollBackProtectedTableSealingKey fails\n")
		return false
	}
	err := ioutil.WriteFile(sealedKeyFileName, b, 0644)
	if err != nil {
		log.Printf("InitHostRollbackCounterTable: Can't write sealedKeyFile\n")
		return false
	}

	// Save table.
	if !WriteCounterTable(t, tableFileName, newKeys[0:32]) {
		log.Printf("WriteCounterTable failed\n")
		return false
	}

	return true
}

// Read existing table if it exists.
func InitHostRollbackCounterTable(tableFileName string, sealedKeyFileName string) *RollbackCounterTable {
	// Read sealed keys and unseal them.
	blob, err := ioutil.ReadFile(sealedKeyFileName)
	if err != nil  || blob == nil {
		return new(RollbackCounterTable)
	}
	key := unsealRollBackProtectedTableSealingKey(blob)
	if key == nil {
		log.Printf("InitHostRollbackCounterTable: Can't unsealRollBackProtectedTableSealingKey\n")
		return nil
	}

	// Get counter table.
	t := ReadCounterTable(tableFileName, key)
	if t== nil {
		log.Printf("InitHostRollbackCounterTable: Can't ReadCounterTable\n")
		return nil
	}
	return t
}

// Lookup Rollback entry for programName, entryName).
func LookupEntry(table RollbackCounterTable, programName string, entryName string) *RollbackEntry {
	for i := 0; i < len(table.Entries) ; i++ {
		if table.Entries[i].HostedProgramName != nil && *table.Entries[i].HostedProgramName == programName &&
				table.Entries[i].EntryLabel != nil && *table.Entries[i].EntryLabel == entryName {
			return table.Entries[i]
		}
	}
	return nil
}

// Update Rollback entry for programName, entryName).
func UpdateEntry(table *RollbackCounterTable, programName string, entryName string,
		 c *int64) *RollbackEntry {
	ent := LookupEntry(*table, programName, entryName)
	if ent == nil {
		ent = new(RollbackEntry)
		ent.HostedProgramName = &programName
		ent.EntryLabel = &entryName
		zero := int64(0)
		ent.Counter = &zero
		table.Entries = append(table.Entries, ent)
	}
	if c != nil {
		ent.Counter = c
	}
	return ent 
}

// Host implementation of rollback protected seal.
func RollBackSeal(table *RollbackCounterTable, labelName string, data []byte) []byte {
	tableEnt := UpdateEntry(table, *getHostedProgramName(), labelName, nil)
	if tableEnt == nil {
		return nil
	}

	c := tableEnt.Counter
	*c = *c + 1
	tableEnt.Counter = c
	tableEnt = UpdateEntry(table, *getHostedProgramName(), labelName, c)
	if tableEnt == nil {
		log.Printf("RollBackSeal: Can't update\n")
		return nil
	}

	e := new(RollbackSealedData)
	e.Entry = new(RollbackEntry)
	e.Entry.HostedProgramName = getHostedProgramName()
	e.Entry.EntryLabel = &labelName
	e.Entry.Counter = c
	e.ProtectedData = data
	return seal(*e)
}

// Host implementation of rollback protected unseal.
func RollBackUnseal(table *RollbackCounterTable, sealed []byte) *RollbackSealedData {
	e := unseal(sealed)
	if e == nil  || e.Entry.HostedProgramName == nil || e.Entry.EntryLabel == nil {
		log.Printf("RollBackUnseal: bad arguments\n")
		return nil
	}
	tableEnt := LookupEntry(*table, *e.Entry.HostedProgramName, *e.Entry.EntryLabel)
	if tableEnt == nil {
		log.Printf("RollBackUnseal: %s doesn't exist\n")
		return nil
	}
	if tableEnt.Counter == nil || *tableEnt.Counter != *e.Entry.Counter {
		fmt.Printf("RollBackUnseal: counter mismatch\n")
		return nil
	}
	return e
}

