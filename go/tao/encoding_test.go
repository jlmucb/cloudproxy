//  Copyright (c) 2016, Google Inc.  All rights reserved.
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
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/golang/protobuf/proto"
)

func compareCryptoKey(key1, key2 *CryptoKey) error {
	if *key1.Version != *key2.Version {
		return errors.New("Mismatching Version")
	} else if *key1.Purpose != *key2.Purpose {
		return errors.New("Mismatching Purpose")
	} else if *key1.Algorithm != *key2.Algorithm {
		return errors.New("Mismatching Algorithm")
	} else if bytes.Compare(key1.Key, key2.Key) != 0 {
		return errors.New("Mismatching Key")
	}
	return nil
}

func TestEncodeDecodeCryptoKey(t *testing.T) {
	var err error
	k := &CryptoKey{}
	k.Reset()
	k.Version = CryptoVersion(12).Enum()
	k.Purpose = CryptoKey_CryptoPurpose(34).Enum()
	k.Algorithm = CryptoKey_CryptoAlgorithm(56).Enum()
	k.Key, err = MakeSensitive(32)
	if err != nil {
		t.Fatal(err)
	}
	defer ClearSensitive(k.Key)
	_, err = rand.Read(k.Key)
	if err != nil {
		t.Fatal(err)
	}

	buf, err := proto.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	defer ClearSensitive(buf)

	newK := &CryptoKey{}
	err = proto.Unmarshal(buf, newK)
	if err != nil {
		t.Fatal(err)
	}
	defer ClearSensitive(newK.Key)

	err = compareCryptoKey(newK, k)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncodeDecodeCryptoKeyset(t *testing.T) {
	startKeys, err := NewTemporaryKeys(Signing | Crypting | Deriving)
	if err != nil {
		t.Fatal(err)
	}

	ks, err := MarshalKeyset(startKeys)
	if err != nil {
		t.Fatal(err)
	}

	for _, key := range ks.Keys {
		defer ClearSensitive(key.Key)
	}

	buf, err := proto.Marshal(ks)
	if err != nil {
		t.Fatal(err)
	}
	defer ClearSensitive(buf)

	newKs := &CryptoKeyset{}

	err = proto.Unmarshal(buf, newKs)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range newKs.Keys {
		defer ClearSensitive(key.Key)
	}

	if len(newKs.Keys) != len(ks.Keys) {
		t.Fatal("Mismatching number of keys:", len(ks.Keys), len(newKs.Keys))
	}
	for k := range ks.Keys {
		err = compareCryptoKey(ks.Keys[k], newKs.Keys[k])
		if err != nil {
			t.Fatal(err)
		}
	}
}
