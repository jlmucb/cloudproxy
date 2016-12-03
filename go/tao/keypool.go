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

import "syscall"

func makeSensitive(length int) ([]byte, error) {
	return syscall.Mmap(-1, 0, length, syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
}

func clearSensitive(b []byte) error {
	ZeroBytes(b)
	return syscall.Munmap(b)
}

type KeyPool struct {
	// maintain list of keys
	keys []*[]byte
}

func NewKeyPool() *KeyPool {
	kp := &KeyPool{}
	return kp
}

func (kp *KeyPool) NewKey(length int) (*[]byte, error) {
	key, err := makeSensitive(length)
	if err != nil {
		return nil, err
	}
	kp.keys = append(kp.keys, &key)
	return &key, nil
}

func (kp *KeyPool) DeleteKey(key *[]byte) error {
	for k, keyPtr := range kp.keys {
		if keyPtr == key {
			kp.keys[k] = kp.keys[len(kp.keys)-1]
			kp.keys = kp.keys[:len(kp.keys)-1]
			break
		}
	}
	return clearSensitive(*key)
}
