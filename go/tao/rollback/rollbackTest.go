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

package main

import (
	"flag"
	"fmt"

  	"github.com/jlmucb/cloudproxy/go/tao"
)

func main() {
	currentCtr := flag.Int64("ctr", 1, "Host counter")
	tablePath  := flag.String("table_path", "ctr_table", "The counter table")
	sealedHostKeyFileName := flag.String("sealedHostKeyFileName", "sealed_host_key", "Sealed host keys")

	flag.Parse()
	fmt.Printf("\nrollbacktest.  ctr: %d, table_path: %s\n", *currentCtr, *tablePath)

	var table *tao.RollbackCounterTable

	tao.SetHostCounter(*currentCtr)
	hostKey := []byte {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
			   0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
	                   0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
			   0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf }
	tao.SetFakeSealedHostKey(hostKey, *sealedHostKeyFileName)

	table = tao.InitHostRollbackCounterTable(*tablePath, *sealedHostKeyFileName)
	if table == nil {
		fmt.Printf("InitHostRollbackCounterTable fails\n")
		return
	}
	fmt.Printf("\nNumber of initial table entries: %d\n", len(table.Entries))

	fmt.Printf("\n")
	secret1Name := "secret1_name"
	secretData := []byte{0,1,2,3,4,5,6,7,8}
	b := tao.RollBackSeal(table, secret1Name, secretData)
	if b == nil {
		fmt.Printf("tao.RollBackSeal failed\n")
		return
	}

	tao.PrintTable(table)
	fmt.Printf("\n")

	// Do it again, this should bump counter
	b = tao.RollBackSeal(table, secret1Name, secretData)
	if b == nil {
		fmt.Printf("tao.RollBackSeal failed\n")
		return
	}

	fmt.Printf("Number table entries after tao.RollBackSeal: %d\n", len(table.Entries))
	if !tao.SaveHostCounterTableWithNewKeys(*sealedHostKeyFileName, *tablePath, table) {
		fmt.Printf("SaveHostCounterTableWithNewKeys failed\n")
	}

	c := tao.RollBackUnseal(table, b)
	if c == nil {
		fmt.Printf("tao.RollBackUnseal failed\n")
		return
	}
	fmt.Printf("Initial secret: %x, Recovered secret: %x\n", secretData, c.ProtectedData)
	tao.PrintTable(table)
	fmt.Printf("\n")

	table = tao.InitHostRollbackCounterTable(*tablePath, *sealedHostKeyFileName)
	if table == nil {
		fmt.Printf("InitHostRollbackCounterTable fails\n")
		return
	}
	fmt.Printf("Number table entries after recovery: %d\n", len(table.Entries))
	tao.PrintTable(table)
	nc := tao.RollBackUnseal(table, b)
	if nc == nil {
		fmt.Printf("tao.RollBackUnseal 2 failed\n")
		return
	}
	fmt.Printf("\nStored secret: %x, New recovered secret: %x\n", secretData, nc.ProtectedData)
	fmt.Println("\nrollbacktest finishing")
}
