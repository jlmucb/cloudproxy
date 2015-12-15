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

// Package tpm supports direct communication with a tpm device under Linux.
package tpm

import (
	//"crypto"
	//"crypto/hmac"
	//"crypto/rand"
	//"crypto/rsa"
	//"crypto/sha1"
	//"crypto/subtle"
	//"bytes"
	//"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
)

// OpenTPM opens a channel to the TPM at the given path. If the file is a
// device, then it treats it like a normal TPM device, and if the file is a
// Unix domain socket, then it opens a connection to the socket.
func OpenTPM(path string) (io.ReadWriteCloser, error) {
	// If it's a regular file, then open it
	var rwc io.ReadWriteCloser
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if fi.Mode()&os.ModeDevice != 0 {
		var f *os.File
		f, err = os.OpenFile(path, os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		rwc = io.ReadWriteCloser(f)
	} else if fi.Mode()&os.ModeSocket != 0 {
		uc, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			return nil, err
		}
		rwc = io.ReadWriteCloser(uc)
	} else {
		return nil, fmt.Errorf("unsupported TPM file mode %s", fi.Mode().String())
	}

	return rwc, nil
}

// ConstructReadPcr constructs a ReadPcr command.
func ConstructReadPcr(pcr uint32) ([]byte, error) {
	return nil, nil
}

// ConstructReadClock constructs a ReadClock command.
func ConstructReadClock(keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// ConstructGetRandom constructs a GetRandom command.
func ConstructGetRandom(size uint32) ([]byte, error) {
	cmdHdr, err := MakeCommandHeader(tagNO_SESSIONS, 0, cmdGetRandom)
	if err != nil {
		return nil, errors.New("ConstructGetRandom failed")
	}
	num_bytes :=  []interface{}{uint16(size)}
	x, _ := packWithHeader(cmdHdr, num_bytes)
	return x, nil
}

// ConstructGetCapabilities constructs a GetCapabilities command.
func ConstructGetCapabilities(keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// ConstructFlushContext constructs a FlushContext command.
func ConstructFlushContext(keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// ConstructLoadKey constructs a LoadKey command.
func ConstructLoadKey(keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// ConstructCreatePrimary constructs a CreatePrimary command.
func ConstructCreatePrimary(keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// ConstructPolicyPassword constructs a PolicyPassword command.
func ConstructPolicyPassword(keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// ConstructPolicyGetDigest constructs a PolicyGetDigest command.
func ConstructPolicyGetDigest(keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// ConstructStartAuthSession constructs a StartAuthSession command.
func ConstructStartAuthSession(keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// ConstructCreateSealed constructs a CreateSealed command.
func ConstructCreateSealed(keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// ConstructCreateKey constructs a CreateKey command.
func ConstructCreateKey(keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// ConstructUnseal constructs a Unseal command.
func ConstructUnseal(keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// ConstructQuote constructs a Quote command.
func ConstructQuote(keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// ConstructActivateCredential constructs a ActivateCredential command.
func ConstructActivateCredential(keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// ConstructReadPublic constructs a ReadPublic command.
func ConstructReadPublic(keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// ConstructEvictControl constructs a EvictControl command.
func ConstructEvictControl(keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// DecodeReadPcr constructs a ReadPcr command.
func DecodeReadPcr(in []byte) ([]byte, error) {
	return nil, nil
}

// DecodeReadClock constructs a ReadClock command.
func DecodeReadClock(in []byte) ([]byte, error) {
	return nil, nil
}

// DecodeGetRandom constructs a GetRandom command.
func DecodeGetRandom(in []byte) ([]byte, error) {
        var rand_bytes []byte

	fmt.Printf("DecodeGetRandom %x\n", in)
        out :=  []interface{}{&rand_bytes}
        err := unpack(in, out)
        if err != nil {
                return nil, errors.New("Can't decode GetRandom response")
        }

        return rand_bytes, nil
}

// DecodeGetCapabilities constructs a GetCapabilities command.
func DecodeGetCapabilities(in []byte) ([]byte, error) {
	return nil, nil
}

// DecodeFlushContext constructs a FlushContext command.
func DecodeFlushContext(in []byte) ([]byte, error) {
	return nil, nil
}

// DecodeLoadKey constructs a LoadKey command.
func DecodeLoadKey(in []byte) ([]byte, error) {
	return nil, nil
}

// DecodeCreatePrimary constructs a CreatePrimary command.
func DecodeCreatePrimary(in []byte) ([]byte, error) {
	return nil, nil
}

// DecodePolicyPassword constructs a PolicyPassword command.
func DecodePolicyPassword(in []byte) ([]byte, error) {
	return nil, nil
}

// DecodePolicyGetDigest constructs a PolicyGetDigest command.
func DecodePolicyGetDigest(in []byte) ([]byte, error) {
	return nil, nil
}

// DecodeStartAuthSession constructs a StartAuthSession command.
func DecodeStartAuthSession(in []byte) ([]byte, error) {
	return nil, nil
}

// DecodeCreateSealed constructs a CreateSealed command.
func DecodeCreateSealed(in []byte) ([]byte, error) {
	return nil, nil
}

// DecodeCreateKey constructs a CreateKey command.
func DecodeCreateKey(in []byte) ([]byte, error) {
	return nil, nil
}

// DecodeUnseal constructs a Unseal command.
func DecodeUnseal(in []byte) ([]byte, error) {
	return nil, nil
}

// DecodeQuote constructs a Quote command.
func DecodeQuote(in []byte) ([]byte, error) {
	return nil, nil
}

// DecodeActivateCredential constructs a ActivateCredential command.
func DecodeActivateCredential(in []byte) ([]byte, error) {
	return nil, nil
}

// DecodeReadPublic constructs a ReadPublic command.
func DecodeReadPublic(in []byte) ([]byte, error) {
	return nil, nil
}

// DecodeEvictControl constructs a EvictControl command.
func DecodeEvictControl(in []byte) ([]byte, error) {
	return nil, nil
}

// ReadPcr reads a PCR value from the TPM.
func ReadPcr(rw io.ReadWriter, pcr uint32) ([]byte, error) {
	return nil, nil
}

// ReadPcrs gets a given sequence of PCR values.
func ReadPcrs(rw io.ReadWriter, pcrVals []int) ([]byte, error) {
	return nil, nil
}

func ReadClock(rw io.ReadWriter, keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// GetRandom gets random bytes from the TPM.
func GetRandom(rw io.ReadWriter, size uint32) ([]byte, error) {
	// Construct command
	x, err:= ConstructGetRandom(size)
	if err != nil {
		fmt.Printf("MakeCommandHeader failed %s\n", err)
		return nil, err
	}

	// Send command
	written, err := rw.Write(x)
	if err != nil {
		fmt.Printf("Write command %s\n", err)
		return nil, err
	}
	fmt.Printf("%d bytes written\n", written)  // remove

	// Get response
	var resp []byte
	read, err := rw.Read(resp)
        if err != nil || read <= 0 {
                return nil, errors.New(" --- Read Tpm fails")
        }
        fmt.Printf("%d bytes read\n", read)  // remove

	// Decode Response
	tag, size, status, err := DecodeCommandResponse(resp[0:10])
	if err != nil {
		fmt.Printf("DecodeCommandResponse %s\n", err)
		return nil,err
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)  // remove
	if status != errSuccess {
	}
	fmt.Printf("resp[10:]: %x\n", resp[10:])
	rand, err :=  DecodeGetRandom(resp[10:])
	if err != nil {
		fmt.Printf("DecodeGetRandom %s\n", err)
		return nil,err
	}
	fmt.Printf("rand: %x\n", rand)
	return rand, nil
}

// GetCapabilities 
func GetCapabilities(rw io.ReadWriter, keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// FlushContext
func FlushContext(rw io.ReadWriter, keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// Flushall
func Flushall(rw io.ReadWriter, keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// LoadKey
func LoadKey(rw io.ReadWriter, keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// CreatePrimary
func CreatePrimary(rw io.ReadWriter, keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// PolicyPassword
func PolicyPassword(rw io.ReadWriter, keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// PolicyGetDigest
func PolicyGetDigest(rw io.ReadWriter, keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// StartAuthSession
func StartAuthSession(rw io.ReadWriter, keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// CreateSealed
func CreateSealed(rw io.ReadWriter, keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// CreateKey
func CreateKey(rw io.ReadWriter, keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// Unseal
func Unseal(rw io.ReadWriter, keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// Quote
func Quote(rw io.ReadWriter, keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// ActivateCredential
func ActivateCredential(rw io.ReadWriter, keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// ReadPublic
func ReadPublic(rw io.ReadWriter, keyBlob []byte) ([]byte, error) {
	return nil, nil
}

// EvictControl
func EvictControl(rw io.ReadWriter, keyBlob []byte) ([]byte, error) {
	return nil, nil
}

