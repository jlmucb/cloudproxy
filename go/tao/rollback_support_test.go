// Copyright (c) 2014-2016, Google Inc. All rights reserved.
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

package tao

import (
	// "fmt"
	"testing"
)

func TestRollback(t *testing.T) {
	tableKey := []byte {
		0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 
		0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 
		}
	t1 := ReadRollbackTable("/tmp/testtable", tableKey)
	if t1 == nil {
		t.Fatal("ReadRollbackTable failed")
	}
	programName := "testProgram"
	entryName := "firstEntry"
	e := t1.LookupRollbackEntry(programName, entryName)
	if e != nil {
		t.Fatal("LookupRollbackEntry should have failed")
	}
	c := int64(1)
	e = t1.UpdateRollbackEntry(programName, entryName, &c)
	if e == nil {
		t.Fatal("UpdateRollbackEntry failed")
	}
	e = t1.UpdateRollbackEntry(programName, "secondEntry", &c)
	if e == nil {
		t.Fatal("UpdateRollbackEntry (2) failed")
	}
	ok := WriteRollbackTable(t1, "/tmp/testtable2", tableKey)
	if !ok {
		t.Fatal("WriteRollbackTable failed")
	}
	t2 := ReadRollbackTable("/tmp/testtable2", tableKey)
	if t2 == nil {
		t.Fatal("ReadRollbackTable failed")
	}
	e = t2.LookupRollbackEntry(programName, entryName)
	if e == nil {
		 t.Fatal("LookupRollbackEntry after reading table failed")
	}
	// e.PrintRollbackEntry()
}

