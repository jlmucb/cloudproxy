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
	"fmt"
)

// A Handle is a 32-bit unsigned integer.
type Handle uint32

// A commandHeader is the header for a TPM command.
type commandHeader struct {
	Tag  uint16
	Size uint32
	Cmd  uint32
}

// String returns a string version of a commandHeader
func (ch commandHeader) String() string {
	return fmt.Sprintf("commandHeader{Tag: %x, Size: %x, Cmd: %x}", ch.Tag, ch.Size, ch.Cmd)
}

// A responseHeader is a header for TPM responses.
type responseHeader struct {
	Tag  uint16
	Size uint32
	Res  uint32
}

type RsaParams struct {
	enc_alg uint16
	hash_alg uint16
	attributes uint32
	auth_policy []byte
	symalg uint16
	sym_sz uint16
	mode uint16
	scheme uint16
	scheme_hash uint16
	mod_sz uint16
	exp uint32
	modulus []byte
}

type KeyedHashParams struct {
	type_alg uint16
	hash_alg uint16
	attributes uint32
	auth_policy []byte
	symalg uint16
        sym_sz uint16
        mode uint16
        scheme uint16
	unique []byte
}

// RSA Key
type RsaKey struct {
	algorithm uint16
	num_key_bits uint16
	mode uint16
	scheme uint16
	modulus []byte
	d []byte
	p []byte
	q []byte
	exponent uint32
}

// Public key
type PublicKey struct {
	key_type uint16
	key RsaKey
}


