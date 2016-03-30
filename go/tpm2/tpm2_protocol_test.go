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

package tpm2

import (
        "testing"
)

func TestCreateKeyHierarchy(t *testing.T) {
	err := CreateTpm2KeyHierarchy(2048, "sha1",
			PrimaryKeyHandle, QuoteKeyHandle, "01020304")
	if (err != nil) {
		t.Fatal("Can't create key hierarchy")
	}
}

func TestGetEndorsementCert(t *testing.T) {
	err := CreateTpm2KeyHierarchy(2048, "sha1",
			PrimaryKeyHandle, QuoteKeyHandle, "01020304")
	if (err != nil) {
		t.Fatal("Can't create key hierarchy")
	}
}

func TestSeal(t *testing.T) {
}

func TestUnseal(t *testing.T) {
}

func TestAttest(t *testing.T) {
}

func TestSignAttest(t *testing.T) {
}

func TestSignProtocol(t *testing.T) {
}

func TestSignProtocolChannel(t *testing.T) {
}

func TestPCR1718(t *testing.T) {
}



