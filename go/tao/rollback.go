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
	"crypto/sha512"
	"errors"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/golang/protobuf/proto"
)

func Protect(keys []byte, in []byte) ([]byte, error) {
	keyType := CrypterTypeFromSuiteName(TaoCryptoSuite)
	if keyType == nil {
		return nil, errors.New("Protect: Can't get key type from cipher suite")
	}
	encKeySize := SymmetricKeySizeFromAlgorithmName(*keyType)
	if encKeySize == nil {
		return nil, errors.New("Protect: Can't get symmetric key size from key type")
	}
	totalKeySize := CombinedKeySizeFromAlgorithmName(*keyType)
	if totalKeySize == nil {
		return nil, errors.New("Protect: Can't get total key size from key type")
	}
	blkSize := SymmetricBlockSizeFromAlgorithmName(*keyType)
	if blkSize == nil {
		return nil, errors.New("Protect: Can't get block size from key type")
	}
	if in == nil {
		return nil, nil
	}
	if len(keys) < *totalKeySize {
		return nil, errors.New("Protect: Supplied key size too small")
	}
	iv := make([]byte, *blkSize, *blkSize)
	_, err := rand.Read(iv[0:*blkSize])
	if err != nil {
		return nil, errors.New("Protect: Can't generate iv")
	}
	encKey := keys[0:*encKeySize]
	macKey := keys[*encKeySize:*totalKeySize]
	crypter, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, errors.New("Protect: Can't make crypter")
	}
	ctr := cipher.NewCTR(crypter, iv)
	cipheredOut := make([]byte, len(in))
	ctr.XORKeyStream(cipheredOut, in)
	ivAndCiphered := append(iv, cipheredOut...)

	var calculatedHmac []byte
	switch(*keyType) {
	default:
		return nil, errors.New("unknown symmetric cipher suite")
	case "aes128-ctr-hmacsha256":
		hm := hmac.New(sha256.New, macKey)
		hm.Write(ivAndCiphered)
		calculatedHmac = hm.Sum(nil)
	case "aes256-ctr-hmacsha384":
		hm := hmac.New(sha512.New384, macKey)
		hm.Write(ivAndCiphered)
		calculatedHmac = hm.Sum(nil)
	case "aes256-ctr-hmacsha512":
		hm := hmac.New(sha512.New, macKey)
		hm.Write(ivAndCiphered)
		calculatedHmac = hm.Sum(nil)
	}
	return append(calculatedHmac, ivAndCiphered...), nil
}

func Unprotect(keys []byte, in []byte) ([]byte, error) {
	keyType := CrypterTypeFromSuiteName(TaoCryptoSuite)
	if keyType == nil {
		return nil, errors.New("Protect: Can't get key type from cipher suite")
	}
	encKeySize := SymmetricKeySizeFromAlgorithmName(*keyType)
	if encKeySize == nil {
		return nil, errors.New("Protect: Can't get symmetric key size from key type")
	}
	hmacKeySize := HmacKeySizeFromAlgorithmName(*keyType)
	if hmacKeySize == nil {
		return nil, errors.New("Protect: Can't get hmac key size from key type")
	}
	hmacSize := HmacKeySizeFromAlgorithmName(*keyType)
	if hmacSize == nil {
		return nil, errors.New("Protect: Can't get hmac size from key type")
	}
	totalKeySize := CombinedKeySizeFromAlgorithmName(*keyType)
	if totalKeySize == nil {
		return nil, errors.New("Protect: Can't get total key size from key type")
	}
	blkSize := SymmetricBlockSizeFromAlgorithmName(*keyType)
	if blkSize == nil {
		return nil, errors.New("Protect: Can't get block size from key type")
	}
	if in == nil {
		return nil, nil
	}
	out := make([]byte, len(in) - *blkSize - *hmacSize, len(in) - *blkSize - *hmacSize)
	iv := in[*hmacSize:*hmacSize + *blkSize]
	encKey := keys[0:*encKeySize]
	macKey := keys[*encKeySize:*totalKeySize]
	crypter, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, errors.New("Unprotect: Can't make crypter")
	}
	ctr := cipher.NewCTR(crypter, iv)
	ctr.XORKeyStream(out, in[*hmacSize + *blkSize:])

	var calculatedHmac []byte
	switch(*keyType) {
	default:
		return nil, errors.New("unknown symmetric cipher suite")
	case "aes128-ctr-hmacsha256":
		hm := hmac.New(sha256.New, macKey)
		hm.Write(in[*hmacSize:])
		calculatedHmac = hm.Sum(nil)
	case "aes256-ctr-hmacsha384":
		hm := hmac.New(sha512.New384, macKey)
		hm.Write(in[*hmacSize:])
		calculatedHmac = hm.Sum(nil)
	case "aes256-ctr-hmacsha512":
		hm := hmac.New(sha512.New, macKey)
		hm.Write(in[*hmacSize:])
		calculatedHmac = hm.Sum(nil)
	}
	if bytes.Compare(calculatedHmac, in[0:*hmacSize]) != 0 {
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
