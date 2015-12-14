// Copyright (c) 2014, Google Inc. All rights reserved.
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

package tpm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
)

func TestDecode(t *testing.T) {
	x, err := ConstructGetRandom(16)
	if err != nil {
		fmt.Printf("TestDecode ConstructGetRandom fails\n")
		return
	}
	var b []byte
        buf := bytes.NewBuffer(b)
	fmt.Printf("TestDecode Constructed command: %x\n", x)
	binary.Write(buf, binary.BigEndian, x)
	fmt.Printf("SIZE: %d\n", len(buf.Bytes()))
	var a1 uint16 
	var a2 uint32
	var a3 uint32
	var a4 uint32
	out :=  []interface{}{&a1, &a2, &a3, &a4}
	err = unpackType(buf, out)
	if err != nil {
		fmt.Printf("unpack breaks\n")
		return
	}
	for _, e := range out {
		v := reflect.ValueOf(e)
                switch v.Kind() {
		case reflect.Ptr:
			switch(reflect.Indirect(v).Kind()) {
			case reflect.Uint16:
				u := reflect.Indirect(v)
				t, ok := u.Interface().(uint16)
				if ok != true {
					fmt.Printf("Not OK\n")
					return
				}
				fmt.Printf("uint16 subcase: %x\n", t)
			case reflect.Uint32:
				u := reflect.Indirect(v)
				t, ok := u.Interface().(uint32)
				if ok != true {
					fmt.Printf("Not OK\n")
					return
				}
				fmt.Printf("uint32 subcase: %x\n", t)
			default:
				fmt.Printf("default subcase\n")
			}
		default:
			fmt.Printf("default case\n")
		}
	}
}

func TestGetRandom(t *testing.T) {
	fmt.Printf("TestGetRandom\n")
	x, err:= ConstructGetRandom(16)
	if err != nil {
		fmt.Printf("makeCommandHeader failed %s\n", err)
		return 
	}
	fmt.Printf("Constructed command: %x\n", x)
	// Send command
	// Get response
	// Decode Response
}

// TestReadPcr tests a ReadPcr command.
func TestReadPcr(t *testing.T) {
}

// TestReadClock tests a ReadClock command.
func TestReadClock(t *testing.T) {
}

// TestGetCapabilities tests a GetCapabilities command.
func TestGetCapabilities(t *testing.T) {
}

// TestFlushContext tests a FlushContext command.
func TestFlushContext(t *testing.T) {
}

// TestLoadKey tests a LoadKey command.
func TestLoadKey(t *testing.T) {
}

// TestCreatePrimary tests a CreatePrimary command.
func TestCreatePrimary(t *testing.T) {
}

// TestPolicyPassword tests a PolicyPassword command.
func TestPolicyPassword(t *testing.T) {
}

// TestPolicyGetDigest tests a PolicyGetDigest command.
func TestPolicyGetDigest(t *testing.T) {
}

// TestStartAuthSession tests a StartAuthSession command.
func TestStartAuthSession(t *testing.T) {
}

// TestCreateSealed tests a CreateSealed command.
func TestCreateSealed(t *testing.T) {
}

// TestCreateKey tests a CreateKey command.
func TestCreateKey(t *testing.T) {
}

// TestUnseal tests a Unseal command.
func TestUnseal(t *testing.T) {
}

// TestQuote tests a Quote command.
func TestQuote(t *testing.T) {
}

// TestActivateCredential tests a ActivateCredential command.
func TestActivateCredential(t *testing.T) {
}

// TestReadPublic tests a ReadPublic command.
func TestReadPublic(t *testing.T) {
}

// TestEvictControl tests a EviceControl command.
func TestEvictControl(t *testing.T) {
}

