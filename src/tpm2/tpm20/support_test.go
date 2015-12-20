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
	"fmt"
	"testing"
)

func TestSetShortPcrs(t *testing.T) {
	pcr_nums := []int{7,8}
	pcr, err := SetShortPcrs(pcr_nums)
	if err != nil {
		t.Fatal("Test SetShortPcrs fails\n")
	}
	fmt.Printf("Pcr's: %x\n", pcr)
	test_pcr := []byte{0x03,0x80,0x01,0x00}
	if !bytes.Equal(test_pcr, pcr) {
		t.Fatal("Wrong pcr value\n")
	}
}

func TestSetHandle(t *testing.T) {
	hand := SetHandle(Handle(ordTPM_RH_OWNER))
	if hand == nil {
		t.Fatal("Test SetHandle fails\n")
	}
	test_out := []byte{0x40, 0, 0, 1}
	if !bytes.Equal(test_out, hand)  {
		t.Fatal("Test SetHandle bad output\n")
	}
	fmt.Printf("TestHandle: %x\n", hand)
}

func TestSetPasswordData(t *testing.T) {
	pw1 := SetPasswordData("01020304")
	test1 := []byte{0,4,1,2,3,4}
	if pw1 == nil || !bytes.Equal(test1, pw1) {
		t.Fatal("Test Password 1 fails\n")
	}
	pw2 := SetPasswordData("0102030405")
	test2 := []byte{0,5,1,2,3,4,5}
	if pw2 == nil || !bytes.Equal(test2, pw2) {
		t.Fatal("Test Password 2 fails\n")
	}
}

func TestCreatePasswordAuthArea(t *testing.T) {
	pw_auth1 := CreatePasswordAuthArea("01020304")
	fmt.Printf("TestCreatePasswordAuthArea: %x\n", pw_auth1)
	test1 := []byte{0,0xd,0x40,0,0,9,0,0,1,0,4,1,2,3,4}
	if test1 == nil || !bytes.Equal(test1, pw_auth1) {
		t.Fatal("Test PasswordAuthArea 1 fails\n")
	}

	pw_auth2 := CreatePasswordAuthArea("")
	test2 := []byte{0,0x9,0x40,0,0,9,0,0,1,0,0}
	if test2 == nil || !bytes.Equal(test1, pw_auth1) {
		t.Fatal("Test PasswordAuthArea 2 fails\n")
	}
	fmt.Printf("TestCreatePasswordAuthArea: %x\n", pw_auth2)
}

func TestCreateSensitiveArea(t *testing.T) {
	a1 := []byte{1,2,3,4}
	var a2 []byte
	s := CreateSensitiveArea(a1, a2)
	if s == nil {
		t.Fatal("CreateSensitiveArea fails")
	}
	test := []byte{0, 8, 0, 4, 1, 2, 3, 4,0,0}
	if !bytes.Equal(test, s) {
		t.Fatal("CreateSensitiveArea fails")
	}
	fmt.Printf("Sensitive area: %x\n", s)
}

func TestCreateRsaParams(t *testing.T) {
	var empty []byte
	parms := RsaParams{uint16(algTPM_ALG_RSA), uint16(algTPM_ALG_SHA1),
		uint32(0x00030072), empty, uint16(algTPM_ALG_AES), uint16(128),
		uint16(algTPM_ALG_CFB), uint16(algTPM_ALG_NULL), uint16(0),
		uint16(1024), uint32(0x00010001), empty}

	s := CreateRsaParams(parms)
	if s == nil {
		t.Fatal("CreateRsaParams fails")
	}
	fmt.Printf("RsaParams area: %x\n", s)
/*
	test := []byte{0,6,0,0x80,0,0x43, 0, 0x10, 4,0,0,1,0,1,0,0}
	if !bytes.Equal(test, s) {
		t.Fatal("CreateRsaParams fails")
	}
*/
}

func TestCreateLongPcr(t *testing.T) {
	s :=  CreateLongPcr(uint32(1), []int{7})
	test := []byte{0, 0, 0, 1, 0, 4, 3, 0x80, 0, 0}
	if !bytes.Equal(test, s) {
		t.Fatal("CreateRsaParams fails")
	}
	fmt.Printf("CreateLongPcr: %x\n", s)
}

