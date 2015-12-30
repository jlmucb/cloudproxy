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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	// "crypto/x509/pkix"
	"encoding/hex"
	//"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
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

func PrintKeyedHashParams(parms *KeyedHashParams) {
        fmt.Printf("type_alg   : %x\n", parms.type_alg)
	fmt.Printf("hash_alg   : %x\n", parms.hash_alg)
        fmt.Printf("attributes : %x\n", parms.attributes)
        fmt.Printf("auth_policy: %x\n", parms.auth_policy)
        fmt.Printf("symalg     : %x\n", parms.symalg)
        fmt.Printf("sym_sz     : %x\n", parms.sym_sz)
        fmt.Printf("mode       : %x\n", parms.mode)
        fmt.Printf("scheme     : %x\n", parms.scheme)
        fmt.Printf("unique     : %x\n", parms.unique)
}

func PrintRsaParams(parms *RsaParams) {
        fmt.Printf("enc_alg :%x\n", parms.enc_alg)
        fmt.Printf("hash_alg :%x\n", parms.hash_alg)
        fmt.Printf("attributes :%x\n", parms.attributes)
        fmt.Printf("auth_policy :%x\n", parms.auth_policy)
        fmt.Printf("symalg :%x\n", parms.symalg)
        fmt.Printf("sym_sz :%x\n", parms.sym_sz)
        fmt.Printf("mode :%x\n", parms.mode)
        fmt.Printf("scheme :%x\n", parms.scheme)
        fmt.Printf("scheme_hash :%x\n", parms.scheme_hash)
        fmt.Printf("modulus size :%x\n", parms.mod_sz)
        fmt.Printf("exp :%x\n", parms.exp)
        fmt.Printf("modulus :%x\n", parms.modulus)
}

func SetShortPcrs(pcr_nums []int) ([]byte, error) {
	pcr := []byte{3,0,0,0}
	var byte_num int
	var byte_pos byte
	for _,e := range pcr_nums {
		byte_num = 1+ e / 8;
		byte_pos = 1 << uint16(e % 8)
		pcr[byte_num] |= byte_pos
	}
	return pcr, nil
}

// nil is error
func SetHandle(handle Handle) ([]byte) {
	uint32_handle := uint32(handle)
	str,_ := pack([]interface{}{&uint32_handle})
	return str
}

// nil return is an error
func SetPasswordData(password string) ([]byte) {
// len password
	pw, err := hex.DecodeString(password)
	if err != nil {
		return nil
	}
	ret, _ := pack([]interface{}{&pw})
	return ret
}

// nil return is an error
// 	returns: len0 TPM_RS_PW 0000 01 password data as []byte
func CreatePasswordAuthArea(password string, owner Handle) ([]byte) {
	owner_str := SetHandle(owner)
	suffix := []byte{0, 0, 1}
	pw := SetPasswordData(password)
	final_buf := append(owner_str, suffix...)
	final_buf = append(final_buf, pw...)
	out := []interface{}{&final_buf}
	ret, _:= pack(out)
	return ret
}

// nil is error
func CreateSensitiveArea(in1 []byte, in2 []byte) ([]byte) {
//   password (SENSITIVE CREATE)
//   0008 0004 01020304
//        0000
	t1, err := pack([]interface{}{&in1})
	if err != nil {
		return nil
	}
	t2, err := pack([]interface{}{&in2})
	if err != nil {
		return nil
	}

	t := append(t1, t2...)
	ret, err := pack([]interface{}{&t})
	if err != nil {
		return nil
	}

	return ret 
}

func DecodeRsaArea(in []byte) (*RsaParams, error) {
	parms := new(RsaParams)
	fmt.Printf("DecodeRsaArea : %x\n", in)
	var rsa_buf []byte
	var current int

        template := []interface{}{&rsa_buf}
        err := unpack(in, template)
        if err != nil {
                return nil, errors.New("Can't unpack Rsa buffer 1")
        }

	current = 0
	template = []interface{}{&parms.enc_alg, &parms.hash_alg,
                                   &parms.attributes, &parms.auth_policy}
        err = unpack(rsa_buf[current:], template)
        if err != nil {
                return nil, errors.New("Can't unpack Rsa buffer 2")
        }
	current += 10 + len(parms.auth_policy)
        template = []interface{}{&parms.symalg, &parms.sym_sz,
                                   &parms.mode, &parms.scheme}
        err = unpack(rsa_buf[current:], template)
        if err != nil {
                return nil, errors.New("Can't unpack Rsa buffer 3")
        }
	current += 8
        if parms.scheme == uint16(algTPM_ALG_RSASSA) {
                template = []interface{}{&parms.scheme_hash}
                err = unpack(rsa_buf[current:], template)
                if err != nil {
                        return nil, errors.New("Can't unpack Rsa buffer 4")
                }
		current += 2
        }

        template = []interface{}{&parms.mod_sz, &parms.exp, &parms.modulus}
        err = unpack(rsa_buf[current:], template)
        if err != nil {
                return nil, errors.New("Can't unpack Rsa buffer 5")
        }
	return parms, nil
}

// nil is error
func CreateKeyedHashParams(parms KeyedHashParams) ([]byte) {
	// 0 (uint16), type, attributes, auth, scheme, 0 (unique)
	template := []interface{}{&parms.type_alg, &parms.hash_alg,
			&parms.attributes, &parms.auth_policy, &parms.scheme,
			&parms.unique}
	t1, err := pack(template)
	if err != nil {
		return nil
	}
	return t1
}

// nil return is error
func CreateRsaParams(parms RsaParams) ([]byte) {
	template1 := []interface{}{&parms.enc_alg, &parms.hash_alg,
				   &parms.attributes, &parms.auth_policy}
	t1, err := pack(template1)
	if err != nil {
		return nil
	}
	template2 := []interface{}{&parms.symalg, &parms.sym_sz,
				   &parms.mode, &parms.scheme}
	t2, err := pack(template2)
	if err != nil {
		return nil
	}
	if parms.scheme == uint16(algTPM_ALG_RSASSA) {
		template3 := []interface{}{&parms.scheme_hash}
		t3, err := pack(template3)
		if err != nil {
			return nil
		}
		t2 = append(t2, t3...)
	}

	template4 := []interface{}{&parms.mod_sz, &parms.exp, parms.modulus}
	t4, err := pack(template4)
	if err != nil {
		return nil
	}

	t5 := append(t1, t2...)
	t5 = append(t5, t4...)
	template5 := []interface{}{&t5}
	buf, err := pack(template5)
	if err != nil {
		return nil
	}
	return buf
}

// nil return is error
func CreateLongPcr(count uint32, pcr_nums []int) ([]byte) {
	b1, err :=  SetShortPcrs(pcr_nums)
	if err != nil {
		return nil
	}
	template := []interface{}{&count, &b1}
	b2, err := pack(template)
	if err != nil {
		return nil
	}
	return b2
}

// ConstructGetRandom constructs a GetRandom command.
func ConstructGetRandom(size uint32) ([]byte, error) {
	cmdHdr, err := MakeCommandHeader(tagNO_SESSIONS, 0, cmdGetRandom)
	if err != nil {
		return nil, errors.New("ConstructGetRandom failed")
	}
	num_bytes :=  []interface{}{uint16(size)}
	cmd, _ := packWithHeader(cmdHdr, num_bytes)
	return cmd, nil
}

// DecodeGetRandom decodes a GetRandom response.
func DecodeGetRandom(in []byte) ([]byte, error) {
        var rand_bytes []byte

        out :=  []interface{}{&rand_bytes}
        err := unpack(in, out)
        if err != nil {
                return nil, errors.New("Can't decode GetRandom response")
        }
        return rand_bytes, nil
}

// GetRandom gets random bytes from the TPM.
func GetRandom(rw io.ReadWriteCloser, size uint32) ([]byte, error) {
	// Construct command
	x, err:= ConstructGetRandom(size)
	if err != nil {
		fmt.Printf("MakeCommandHeader failed %s\n", err)
		return nil, err
	}

	// Send command
	_, err = rw.Write(x)
	if err != nil {
		return nil, errors.New("Write Tpm fails") 
	}

	// Get response
	var resp []byte
	resp = make([]byte, 1024, 1024)
	read, err := rw.Read(resp)
        if err != nil {
                return nil, errors.New("Read Tpm fails")
        }

	// Decode Response
        if read < 10 {
                return nil, errors.New("Read buffer too small")
	}
	tag, size, status, err := DecodeCommandResponse(resp[0:10])
	if err != nil {
		fmt.Printf("DecodeCommandResponse %s\n", err)
		return nil, err
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)  // remove
	if status != errSuccess {
	}
	rand, err :=  DecodeGetRandom(resp[10:read])
	if err != nil {
		fmt.Printf("DecodeGetRandom %s\n", err)
		return nil,err
	}
	return rand, nil
}

// ConstructFlushContext constructs a FlushContext command.
func ConstructFlushContext(handle Handle) ([]byte, error) {
	cmdHdr, err := MakeCommandHeader(tagNO_SESSIONS, 0, cmdFlushContext)
	if err != nil {
		return nil, errors.New("ConstructFlushContext failed")
	}
	cmd_text :=  []interface{}{uint32(handle)}
	x, _ := packWithHeader(cmdHdr, cmd_text)
	return x, nil
}

// FlushContext
func FlushContext(rw io.ReadWriter, handle Handle) (error) {
	// Construct command
	cmd, err:= ConstructFlushContext(handle)
	if err != nil {
		return errors.New("ConstructFlushContext fails") 
	}

	// Send command
	_, err = rw.Write(cmd)
	if err != nil {
		return errors.New("Write Tpm fails") 
	}

	// Get response
	var resp []byte
	resp = make([]byte, 1024, 1024)
	read, err := rw.Read(resp)
        if err != nil {
                return errors.New("Read Tpm fails")
        }

	// Decode Response
        if read < 10 {
                return errors.New("Read buffer too small")
	}
	tag, size, status, err := DecodeCommandResponse(resp[0:10])
	if err != nil {
                return errors.New("DecodeCommandResponse fails")
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)
	if status != errSuccess {
		return errors.New("FlushContext unsuccessful")
	}
	return nil
}

// ConstructReadPcrs constructs a ReadPcr command.
func ConstructReadPcrs(num_spec int, num_pcr byte, pcrs []byte) ([]byte, error) {
	cmdHdr, err := MakeCommandHeader(tagNO_SESSIONS, 0, cmdPCR_Read)
	if err != nil {
		return nil, errors.New("ConstructReadPcrs failed")
	}
	num := uint32(num_spec)
	template := []interface{}{&num, &pcrs}
	cmd, _ := packWithHeader(cmdHdr, template)
	return cmd, nil
}

// DecodeReadPcrs decodes a ReadPcr response.
func DecodeReadPcrs(in []byte) (uint32, []byte, uint16, []byte, error) {
        var pcr []byte
        var digest []byte
        var updateCounter uint32
        var t uint32
        var s uint32

        out :=  []interface{}{&t, &updateCounter, &pcr, &s, &digest}
        err := unpack(in, out)
        if err != nil {
                return 1, nil, 0, nil, errors.New("Can't decode ReadPcrs response")
        }
	return updateCounter, pcr, uint16(t), digest, nil
}

// ReadPcr reads a PCR value from the TPM.
//	Output: updatecounter, selectout, digest
func ReadPcrs(rw io.ReadWriter, num_byte byte, pcrSelect []byte) (uint32, []byte, uint16, []byte, error) {
	// Construct command
	x, err:= ConstructReadPcrs(1, 4, pcrSelect)
	if err != nil {
		fmt.Printf("MakeCommandHeader failed %s\n", err)
		return 1, nil, 0, nil, errors.New("MakeCommandHeader failed") 
	}
	fmt.Printf("ReadPcrs command: %x", x)

	// Send command
	_, err = rw.Write(x)
	if err != nil {
		return 0, nil, 0, nil, errors.New("Write Tpm fails") 
	}

	// Get response
	var resp []byte
	resp = make([]byte, 1024, 1024)
	read, err := rw.Read(resp)
        if err != nil {
                return 0, nil, 0, nil, errors.New("Read Tpm fails")
        }

	// Decode Response
        if read < 10 {
                return 0, nil, 0, nil, errors.New("Read buffer too small")
	}
	tag, size, status, err := DecodeCommandResponse(resp[0:10])
	if err != nil {
		return 0, nil, 0, nil, errors.New("DecodeCommandResponse fails")
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)  // remove
	if status != errSuccess {
		return 0, nil, 0, nil, errors.New("ReadPcr command failed")
	}
	counter, pcr, alg, digest, err := DecodeReadPcrs(resp[10:])
	if err != nil {
		return 0, nil, 0, nil, errors.New("DecodeReadPcrsfails")
	}
	return counter, pcr, alg, digest, err 
}

// ConstructReadClock constructs a ReadClock command.
func ConstructReadClock() ([]byte, error) {
	cmdHdr, err := MakeCommandHeader(tagNO_SESSIONS, 0, cmdReadClock)
	if err != nil {
		return nil, errors.New("ConstructGetRandom failed")
	}
	cmd := packWithBytes(cmdHdr, nil)
	return cmd, nil
}

// DecodeReadClock decodes a ReadClock response.
func DecodeReadClock(in []byte) (uint64, uint64, error) {
        var current_time, current_clock uint64

        template :=  []interface{}{&current_time, &current_clock}
        err := unpack(in, template)
        if err != nil {
                return 0, 0, errors.New("Can't decode DecodeReadClock response")
        }
	return current_time, current_clock, nil
}

// ReadClock
//	Output: current time, current clock
func ReadClock(rw io.ReadWriter) (uint64, uint64, error) {
	// Construct command
	x, err:= ConstructReadClock()
	if err != nil {
		fmt.Printf("MakeCommandHeader failed %s\n", err)
		return 0 ,0, err
	}

	// Send command
	_, err = rw.Write(x)
	if err != nil {
		return 0, 0, errors.New("Write Tpm fails") 
	}

	// Get response
	var resp []byte
	resp = make([]byte, 1024, 1024)
	read, err := rw.Read(resp)
        if err != nil {
                return 0, 0, errors.New("Read Tpm fails")
        }

	// Decode Response
        if read < 10 {
                return 0, 0, errors.New("Read buffer too small")
	}
	tag, size, status, err := DecodeCommandResponse(resp[0:10])
	if err != nil {
		fmt.Printf("DecodeCommandResponse %s\n", err)
		return 0, 0, err
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)  // remove
	if status != errSuccess {
	}
	current_time, current_clock, err :=  DecodeReadClock(resp[10:read])
	if err != nil {
		fmt.Printf("DecodeReadClock %s\n", err)
		return 0, 0,err
	}
	return current_time, current_clock, nil
}

// ConstructGetCapabilities constructs a GetCapabilities command.
func ConstructGetCapabilities(cap uint32, count uint32, property uint32) ([]byte, error) {
	cmdHdr, err := MakeCommandHeader(tagNO_SESSIONS, 0, cmdGetCapability)
	if err != nil {
		return nil, errors.New("GetCapability failed")
	}
	cap_bytes:=  []interface{}{&cap, &property, &count}
	cmd, _ := packWithHeader(cmdHdr, cap_bytes)
	return cmd, nil
}

// DecodeGetCapabilities decodes a GetCapabilities response.
func DecodeGetCapabilities(in []byte) (uint32, []uint32, error) {
        var num_handles uint32
        var cap_reported uint32

        out :=  []interface{}{&cap_reported,&num_handles}
        err := unpack(in[1:9], out)
        if err != nil {
                return 0, nil, errors.New("Can't decode GetCapabilities response")
        }
	// only ordTPM_CAP_HANDLES handled
        if cap_reported !=  ordTPM_CAP_HANDLES {
                return 0, nil, errors.New("Only ordTPM_CAP_HANDLES supported")
        }
	var handles []uint32
	var handle uint32
        handle_out :=  []interface{}{&handle}
	for i:= 0; i < int(num_handles); i++ {
		err := unpack(in[8 + 4 * i:18:12 + 4 * i], handle_out)
		if err != nil {
			return 0, nil, errors.New("Can't decode GetCapabilities handle")
		}
		handles = append(handles, handle)
	}

        return cap_reported, handles, nil
}

// GetCapabilities 
//	Output: output buf
func GetCapabilities(rw io.ReadWriter, cap uint32, count uint32, property uint32) ([]uint32, error) {
	// Construct command
	x, err:= ConstructGetCapabilities(cap, count, property)
	if err != nil {
		fmt.Printf("MakeCommandHeader failed %s\n", err)
		return nil, err
	}

	// Send command
	_, err = rw.Write(x)
	if err != nil {
		return nil, errors.New("Write Tpm fails") 
	}

	// Get response
	var resp []byte
	resp = make([]byte, 1024, 1024)
	read, err := rw.Read(resp)
        if err != nil {
                return nil, errors.New("Read Tpm fails")
        }

	// Decode Response
        if read < 10 {
                return nil, errors.New("Read buffer too small")
	}
	tag, size, status, err := DecodeCommandResponse(resp[0:10])
	if err != nil {
		fmt.Printf("DecodeCommandResponse %s\n", err)
		return nil, err
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)  // remove
	if status != errSuccess {
	}
	_, handles, err :=  DecodeGetCapabilities(resp[10:read])
	if err != nil {
		return nil,err
	}
	return handles, nil
}

// Flushall
func Flushall(rw io.ReadWriter) (error) {
	handles, err := GetCapabilities(rw, ordTPM_CAP_HANDLES, 1, 0x80000000)
	if err != nil {
		return err
	}
	for _, e := range handles {
		_ = FlushContext(rw, Handle(e))
	}
	return nil
}

// ConstructCreatePrimary constructs a CreatePrimary command.
func ConstructCreatePrimary(owner uint32, pcr_nums []int,
		parent_password string, owner_password string,
		parms RsaParams) ([]byte, error) {
	cmdHdr, err := MakeCommandHeader(tagSESSIONS, 0, cmdCreatePrimary)
	if err != nil {
		return nil, errors.New("ConstructCreatePrimary failed")
	}
	var empty []byte
	b1 := SetHandle(Handle(owner))
	b2,_ := pack([]interface{}{&empty})
	b3 := CreatePasswordAuthArea(parent_password, Handle(ordTPM_RS_PW))
	t1 := SetPasswordData(owner_password)
	b4 := CreateSensitiveArea(t1[2:], empty)
	b5 := CreateRsaParams(parms)
	b6,_ := pack([]interface{}{&empty})
	b7 := CreateLongPcr(uint32(1), pcr_nums)
	arg_bytes := append(b1, b2...)
	arg_bytes = append(arg_bytes, b3...)
	arg_bytes = append(arg_bytes, b4...)
	arg_bytes = append(arg_bytes, b5...)
	arg_bytes = append(arg_bytes, b6...)
	arg_bytes = append(arg_bytes, b7...)
	cmd_bytes := packWithBytes(cmdHdr, arg_bytes)
	return cmd_bytes, nil
}

// DecodeCreatePrimary decodes a CreatePrimary response.
func DecodeCreatePrimary(in []byte) (Handle, []byte, error) {
	var handle uint32
	var auth []byte

	// handle and auth data
        template :=  []interface{}{&handle, &auth}
        err := unpack(in, template)
        if err != nil {
                return Handle(0), nil, errors.New("Can't decode response 1")
        }

	var current int
	current = 6 + 2*len(auth)
	// size, size-public
	var tpm2_public []byte
        template =  []interface{}{&tpm2_public}
        err = unpack(in[current:], template)
        if err != nil {
                return Handle(0), nil, errors.New("Can't decode CreatePrimary response 2")
        }
	fmt.Printf("tpm2_public : %x %x\n", len(tpm2_public), tpm2_public)

	var rsa_params_buf []byte
        template =  []interface{}{&rsa_params_buf}
        err = unpack(tpm2_public, template)
        if err != nil {
                return Handle(0), nil, errors.New("Can't decode CreatePrimary response 3")
        }
	fmt.Printf("rsa_params_buf: %x %x\n", len(rsa_params_buf), rsa_params_buf)

	// params
	params, err := DecodeRsaArea(tpm2_public)
        if err != nil {
                return Handle(0), nil, err
        } 
	PrintRsaParams(params)

	// Creation data
	current = 2+len(rsa_params_buf)
	var creation_data []byte
        template =  []interface{}{&creation_data}
        err = unpack(tpm2_public[current:], template)
        if err != nil {
                return Handle(0), nil, errors.New("Can't decode CreatePrimary response 4")
	}
	fmt.Printf("creation data: %x\n", creation_data)
	current += len(creation_data) +2

	// Digest
	var digest []byte
        template =  []interface{}{&digest}
        err = unpack(tpm2_public[current:], template)
        if err != nil {
                return Handle(0), nil, errors.New("Can't decode CreatePrimary response 5")
	}
	fmt.Printf("digest : %x\n", digest)
	current += len(digest) +2

	// TPMT_TK_CREATION
	current += 6
	var crap []byte
        template =  []interface{}{&crap}
        err = unpack(tpm2_public[current:], template)
        if err != nil {
                return Handle(0), nil, errors.New("Can't decode CreatePrimary response 5")
	}
	fmt.Printf("crap: %x\n", crap)
	current += len(crap) +2

	// Name
	var name []byte
        template =  []interface{}{&name}
        err = unpack(tpm2_public[current:], template)
        if err != nil {
                return Handle(0), nil, errors.New("Can't decode CreatePrimary response 5")
	}
	fmt.Printf("name: %x\n", name)

	return Handle(handle), tpm2_public, nil
}

// CreatePrimary
//	Output: handle, public key blob
func CreatePrimary(rw io.ReadWriter, owner uint32, pcr_nums []int,
	parent_password, owner_password string, parms RsaParams) (Handle, []byte, error) {

	// Construct command
	cmd, err:= ConstructCreatePrimary(uint32(owner), pcr_nums, parent_password,
		owner_password, parms)
	if err != nil {
		fmt.Printf("MakeCommandHeader failed %s\n", err)
		return Handle(0), nil, err
	}

	// Send command
	_, err = rw.Write(cmd)
	if err != nil {
		return Handle(0), nil, errors.New("Write Tpm fails") 
	}

	// Get response
	var resp []byte
	resp = make([]byte, 2048, 2048)
	read, err := rw.Read(resp)
        if err != nil {
                return Handle(0), nil, errors.New("Read Tpm fails")
        }

	// Decode Response
        if read < 10 {
                return Handle(0), nil, errors.New("Read buffer too small")
	}
	tag, size, status, err := DecodeCommandResponse(resp[0:10])
	if err != nil {
		fmt.Printf("DecodeCommandResponse %s\n", err)
		return Handle(0), nil, err
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)  // remove
	if status != errSuccess {
	}
	handle, public_blob, err :=  DecodeCreatePrimary(resp[10:read])
	if err != nil {
		fmt.Printf("DecodeCreatePrimary %s\n", err)
		return Handle(0), nil, err
	}
	return Handle(handle), public_blob, nil
}

// ConstructReadPublic constructs a ReadPublic command.
func ConstructReadPublic(handle Handle) ([]byte, error) {
	cmdHdr, err := MakeCommandHeader(tagNO_SESSIONS, 0, cmdReadPublic)
	if err != nil {
		return nil, errors.New("ConstructReadPublic failed")
	}
	num_bytes :=  []interface{}{uint32(handle)}
	cmd, _ := packWithHeader(cmdHdr, num_bytes)
	return cmd, nil
}

// DecodeReadPublic decodes a ReadPublic response.
//	public, name, qualified name
func DecodeReadPublic(in []byte) ([]byte, []byte, []byte, error) {
        var public_blob []byte
        var name []byte
        var qualified_name []byte

        out :=  []interface{}{&public_blob, &name, &qualified_name}
        err := unpack(in, out)
        if err != nil {
                return nil, nil, nil, errors.New("Can't decode ReadPublic response")
        }
        return public_blob, name, qualified_name, nil
}

// ReadPublic
//	Output: key blob, name, qualified name
func ReadPublic(rw io.ReadWriter, handle Handle) ([]byte, []byte, []byte, error) {

	// Construct command
	x, err:= ConstructReadPublic(handle)
	if err != nil {
		fmt.Printf("MakeCommandHeader failed %s\n", err)
		return nil, nil, nil, err
	}

	// Send command
	_, err = rw.Write(x)
	if err != nil {
		return nil, nil, nil, errors.New("Write Tpm fails") 
	}

	// Get response
	var resp []byte
	resp = make([]byte, 1024, 1024)
	read, err := rw.Read(resp)
        if err != nil {
                return nil, nil, nil, errors.New("Read Tpm fails")
        }

	// Decode Response
        if read < 10 {
                return nil, nil, nil, errors.New("Read buffer too small")
	}
	tag, size, status, err := DecodeCommandResponse(resp[0:10])
	if err != nil {
		fmt.Printf("DecodeCommandResponse %s\n", err)
		return nil, nil, nil, err
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)  // remove
	if status != errSuccess {
		return nil, nil, nil, err
	}
	public_blob, name, qualified_name, err :=  DecodeReadPublic(resp[10:read])
	if err != nil {
		fmt.Printf("DecodeReadPublic %s\n", err)
		return nil, nil, nil,err
	}
	return public_blob, name, qualified_name, nil
}

// CreateKey

// ConstructCreateKey constructs a CreateKey command.
func ConstructCreateKey(owner uint32, pcr_nums []int, parent_password string, owner_password string,
                parms RsaParams) ([]byte, error) {
	cmdHdr, err := MakeCommandHeader(tagSESSIONS, 0, cmdCreate)
 	if err != nil {
		return nil, errors.New("ConstructCreateKey failed")
	}
 	var empty []byte
 	b1 := SetHandle(Handle(owner))
	b2 ,_ := pack([]interface{}{&empty})
 	b3 := CreatePasswordAuthArea(parent_password, Handle(ordTPM_RS_PW))
 	t1 := SetPasswordData(owner_password)
 	b4 := CreateSensitiveArea(t1[2:], empty)
 	b5 := CreateRsaParams(parms)
	b6 ,_ := pack([]interface{}{&empty})
 	b7:= CreateLongPcr(uint32(1), pcr_nums)
 	arg_bytes := append(b1, b2...)
 	arg_bytes = append(arg_bytes, b3...)
 	arg_bytes = append(arg_bytes, b4...)
 	arg_bytes = append(arg_bytes, b5...)
 	arg_bytes = append(arg_bytes, b6...)
 	arg_bytes = append(arg_bytes, b7...)
	cmd_bytes := packWithBytes(cmdHdr, arg_bytes)
	return cmd_bytes, nil
}

// DecodeCreateKey decodes a CreateKey response.
//	Output: private_blob, public_blob
func DecodeCreateKey(in []byte) ([]byte, []byte, error) {
        var tpm2b_private []byte
        var tpm2b_public []byte

	// auth?
	// tpm2b_private
	// tpm2b_public
        out :=  []interface{}{&tpm2b_private, &tpm2b_public}
        err := unpack(in[4:], out)
        if err != nil {
                return nil, nil, errors.New("Can't decode CreateKey response")
        }
	// creation data
	// tpmt_tk_creation
	// digest
	return tpm2b_private, tpm2b_public, nil
}

// Output: public blob, private blob, digest
func CreateKey(rw io.ReadWriter, owner uint32, pcr_nums []int, parent_password string, owner_password string,
		parms RsaParams) ([]byte, []byte, error) {

	// Construct command
	cmd, err:= ConstructCreateKey(uint32(owner), pcr_nums, parent_password,
                owner_password, parms)
	if err != nil {
		fmt.Printf("MakeCommandHeader failed %s\n", err)
		return nil, nil, err
	}

	// Send command
	_, err = rw.Write(cmd)
	if err != nil {
		return nil, nil, errors.New("Write Tpm fails") 
	}

	// Get response
	var resp []byte
	resp = make([]byte, 1024, 1024)
	read, err := rw.Read(resp)
        if err != nil {
                return nil, nil, errors.New("Read Tpm fails")
        }

	// Decode Response
        if read < 10 {
                return nil, nil, errors.New("Read buffer too small")
	}
	tag, size, status, err := DecodeCommandResponse(resp[0:10])
	if err != nil {
		fmt.Printf("DecodeCommandResponse %s\n", err)
		return nil, nil, err
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)  // remove
	if status != errSuccess {
		return nil, nil, errors.New("Error from command")
	}
	private_blob, public_blob, err :=  DecodeCreateKey(resp[10:read])
	if err != nil {
		fmt.Printf("DecodeCreateKey %s\n", err)
		return nil, nil, err
	}
	return private_blob, public_blob, nil
}

// ConstructLoad constructs a Load command.
func ConstructLoad(parentHandle Handle, parentAuth string, ownerAuth string,
             public_blob []byte, private_blob []byte) ([]byte, error) {
	cmdHdr, err := MakeCommandHeader(tagSESSIONS, 0, cmdLoad)
	if err != nil {
		return nil, errors.New("ConstructLoad failed")
	}
	b1 := SetHandle(parentHandle)
	b3 := SetPasswordData(parentAuth)
	b4 := CreatePasswordAuthArea(ownerAuth, Handle(ordTPM_RS_PW))
	// private, public
	b5,_ := pack([]interface{}{&private_blob, &public_blob})
	arg_bytes := append(b1, b3...)
	arg_bytes = append(arg_bytes, b4...)
	arg_bytes = append(arg_bytes, b5...)
	cmd_bytes := packWithBytes(cmdHdr, arg_bytes)
	return cmd_bytes, nil
}

// DecodeLoad decodes a Load response.
//	handle, name
func DecodeLoad(in []byte) (Handle, []byte, error) {
        var handle uint32
        var auth []byte
        var name []byte

        out :=  []interface{}{&handle, &auth, &name}
        err := unpack(in, out)
        if err != nil {
                return Handle(0), nil, errors.New("Can't decode Load response")
        }
        return Handle(handle), name, nil
}

// Load
//	Output: handle
func Load(rw io.ReadWriter, parentHandle Handle, parentAuth string, ownerAuth string,
	     public_blob []byte, private_blob []byte) (Handle, []byte, error) {

	// Construct command
	cmd, err:= ConstructLoad(parentHandle, parentAuth, ownerAuth, public_blob, private_blob)
	if err != nil {
		fmt.Printf("MakeCommandHeader failed %s\n", err)
		return Handle(0), nil, err
	}

	// Send command
	_, err = rw.Write(cmd)
	if err != nil {
		return Handle(0), nil, errors.New("Write Tpm fails") 
	}

	// Get response
	var resp []byte
	resp = make([]byte, 1024, 1024)
	read, err := rw.Read(resp)
        if err != nil {
                return Handle(0), nil, errors.New("Read Tpm fails")
        }

	// Decode Response
        if read < 10 {
                return Handle(0), nil, errors.New("Read buffer too small")
	}
	tag, size, status, err := DecodeCommandResponse(resp[0:10])
	if err != nil {
		fmt.Printf("DecodeCommandResponse %s\n", err)
		return Handle(0), nil, err
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)  // remove
	if status != errSuccess {
		return Handle(0), nil, errors.New("Error from command")
	}
	handle, name, err :=  DecodeLoad(resp[10:read])
	if err != nil {
		fmt.Printf("DecodeCreateKey %s\n", err)
		return Handle(0), nil, err
	}
	return handle, name, nil
}

// Construct PolicyPcr command.
func ConstructPolicyPcr(handle Handle, expected_digest []byte, pcr_nums []int) ([]byte, error) {
	cmdHdr, err := MakeCommandHeader(tagNO_SESSIONS, 0, cmdPolicyPCR)
	if err != nil {
		return nil, errors.New("ConstructPcr failed")
	}
	u_handle := uint32(handle)
	template :=  []interface{}{&u_handle, &expected_digest}
	b1, err := pack(template)
	if err != nil {
		return nil, errors.New("Can't pack pcr buf")
	}
	b2 := CreateLongPcr(1, pcr_nums)
	cmd := packWithBytes(cmdHdr, append(b1, b2...))
	return cmd, nil
}

// ConstructPolicyPassword constructs a PolicyPassword command.
func ConstructPolicyPassword(handle Handle) ([]byte, error) {
	cmdHdr, err := MakeCommandHeader(tagNO_SESSIONS, 0, cmdPolicyPassword)
	if err != nil {
		return nil, errors.New("ConstructPassword failed")
	}
	u_handle := uint32(handle)
	template :=  []interface{}{&u_handle}
	b1, err := pack(template)
	if err != nil {
		return nil, errors.New("Can't pack pcr buf")
	}
	cmd := packWithBytes(cmdHdr, b1)
	return cmd, nil
}

// PolicyPassword
func PolicyPassword(rw io.ReadWriter, handle Handle) (error) {
	// Construct command
	cmd, err:= ConstructPolicyPassword(handle)
	if err != nil {
		fmt.Printf("MakeCommandHeader failed %s\n", err)
		return err
	}

	// Send command
	_, err = rw.Write(cmd)
	if err != nil {
		return errors.New("Write Tpm fails") 
	}

	// Get response
	var resp []byte
	resp = make([]byte, 1024, 1024)
	read, err := rw.Read(resp)
        if err != nil {
                return errors.New("Read Tpm fails")
        }

	// Decode Response
        if read < 10 {
                return errors.New("Read buffer too small")
	}
	tag, size, status, err := DecodeCommandResponse(resp[0:10])
	if err != nil {
		fmt.Printf("DecodeCommandResponse %s\n", err)
		return err
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)  // remove
	if status != errSuccess {
		return errors.New("Comand failure")
	}
	return nil
}

// ConstructPolicyGetDigest constructs a PolicyGetDigest command.
func ConstructPolicyGetDigest(handle Handle) ([]byte, error) {
	cmdHdr, err := MakeCommandHeader(tagNO_SESSIONS, 0, cmdPolicyGetDigest)
	if err != nil {
		return nil, errors.New("ConstructGetDigest failed")
	}
	u_handle := uint32(handle)
	template :=  []interface{}{&u_handle}
	b1, err := pack(template)
	if err != nil {
		return nil, errors.New("Can't pack pcr buf")
	}
	cmd := packWithBytes(cmdHdr, b1)
	return cmd, nil
}

// DecodePolicyGetDigest decodes a PolicyGetDigest response.
func DecodePolicyGetDigest(in []byte) ([]byte, error) {
        var digest []byte

        out :=  []interface{}{&digest}
        err := unpack(in, out)
        if err != nil {
                return nil, errors.New("Can't decode DecodePolicyGetDigest response")
        }
        return digest, nil
}

// PolicyGetDigest
//	Output: digest
func PolicyGetDigest(rw io.ReadWriter, handle Handle) ([]byte, error) {
	// Construct command
	cmd, err:= ConstructPolicyGetDigest(handle)
	if err != nil {
		fmt.Printf("ConstructPolicyGetDigest failed %s\n", err)
		return nil, err
	}

	// Send command
	_, err = rw.Write(cmd)
	if err != nil {
		return nil, errors.New("Write Tpm fails") 
	}

	// Get response
	var resp []byte
	resp = make([]byte, 1024, 1024)
	read, err := rw.Read(resp)
        if err != nil {
                return nil, errors.New("Read Tpm fails")
        }

	// Decode Response
        if read < 10 {
                return nil, errors.New("Read buffer too small")
	}
	tag, size, status, err := DecodeCommandResponse(resp[0:10])
	if err != nil {
		fmt.Printf("DecodeCommandResponse %s\n", err)
		return nil, err
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)  // remove
	if status != errSuccess {
		return nil, errors.New("Comand failure")
	}
	digest, err := DecodePolicyGetDigest(resp[10:])
	if err != nil {
		return nil, err
	}
	return digest, nil
}

// ConstructStartAuthSession constructs a StartAuthSession command.
func ConstructStartAuthSession(tpm_key Handle, bind_key Handle, nonceCaller []byte, secret []byte,
		se byte, sym []byte, hash_alg uint16) ([]byte, error) {
	// tpm_key
	// bind (TPM_RH_NULL)
	// noncecaller
	// encrypted secret (salt)
	// TPM_SE
	// TPM_SYM_DEF
	// Alg hash
	cmdHdr, err := MakeCommandHeader(tagSESSIONS, 0, cmdStartAuthSession)
 	if err != nil {
		return nil, errors.New("ConstructStartAuthSession failed")
	}
 	b1 := SetHandle(tpm_key)
 	b2 := SetHandle(bind_key)
	b3 ,_ := pack([]interface{}{&nonceCaller})
	// secret and se
 	b4 := []byte{0,0,0,0,0,0,0,0,se}
	b5 ,_ := pack([]interface{}{&sym, &hash_alg})
 	arg_bytes := append(b1, b2...)
 	arg_bytes = append(arg_bytes, b3...)
 	arg_bytes = append(arg_bytes, b4...)
 	arg_bytes = append(arg_bytes, b5...)
	cmd_bytes := packWithBytes(cmdHdr, arg_bytes)
	return cmd_bytes, nil
}

// DecodeStartAuthSession decodes a StartAuthSession response.
//	Output: session_handle, nonce
func DecodeStartAuthSession(in []byte) (Handle, []byte, error) {
	var handle uint32
	var nonce []byte
        template :=  []interface{}{&handle, &nonce}
        err := unpack(in, template)
        if err != nil {
                return Handle(0), nil, errors.New("Can't decode StartAuthSession response")
        }
	return Handle(handle), nonce, nil
}

// StartAuthSession
func StartAuthSession(rw io.ReadWriter, tpm_key Handle, bind_key Handle, nonceCaller []byte, secret []byte,
                se byte, sym []byte, hash_alg uint16) (Handle, []byte, error) {
	
	// Construct command
	cmd, err:= ConstructStartAuthSession(tpm_key, bind_key, nonceCaller, secret,
                se, sym, hash_alg)
	if err != nil {
		return Handle(0), nil, errors.New("ConstructStartAuthSession fails") 
	}

	// Send command
	_, err = rw.Write(cmd)
	if err != nil {
		return Handle(0), nil, errors.New("Write Tpm fails") 
	}

	// Get response
	var resp []byte
	resp = make([]byte, 1024, 1024)
	read, err := rw.Read(resp)
        if err != nil {
                return Handle(0), nil, errors.New("Read Tpm fails")
        }

	// Decode Response
        if read < 10 {
                return Handle(0), nil, errors.New("Read buffer too small")
	}
	tag, size, status, err := DecodeCommandResponse(resp[0:10])
	if err != nil {
                return Handle(0), nil, errors.New("DecodeCommandResponse fails")
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)
	if status != errSuccess {
		return Handle(0), nil, errors.New("StartAuthSession unsuccessful")
	}
	handle, nonce, err := DecodeStartAuthSession(resp[10:])
        if err != nil {
                return Handle(0), nil, errors.New("DecodeStartAuthSession fails")
        }
	return handle, nonce, nil
}

// ConstructCreateSealed constructs a CreateSealed command.
func ConstructCreateSealed(parent Handle, policy_digest []byte,
			   parent_password string, owner_password string,
        		   to_seal []byte, pcr_nums []int,
			   parms KeyedHashParams) ([]byte, error) {
	fmt.Printf("ConstructCreateSealed\n")
	PrintKeyedHashParams(&parms)
	cmdHdr, err := MakeCommandHeader(tagSESSIONS, 0, cmdCreate)
 	if err != nil {
		return nil, errors.New("ConstructCreateKey failed")
	}
 	var empty []byte
 	b1 := SetHandle(parent)
	b2 ,_ := pack([]interface{}{&empty})
 	b3 := CreatePasswordAuthArea(parent_password, Handle(ordTPM_RS_PW))
 	t1 := SetPasswordData(owner_password)
 	b4 := CreateSensitiveArea(t1[2:], to_seal)
	parms.auth_policy =  policy_digest
	b5 := CreateKeyedHashParams(parms)
	b6 ,_ := pack([]interface{}{&b5})
	b7, _ := pack([]interface{}{&empty})
 	b8:= CreateLongPcr(uint32(1), pcr_nums)
 	arg_bytes := append(b1, b2...)
 	arg_bytes = append(arg_bytes, b3...)
 	arg_bytes = append(arg_bytes, b4...)
 	arg_bytes = append(arg_bytes, b6...)
 	arg_bytes = append(arg_bytes, b7...)
 	arg_bytes = append(arg_bytes, b8...)
	cmd_bytes := packWithBytes(cmdHdr, arg_bytes)
	return cmd_bytes, nil
}

// DecodeCreateSealed decodes a CreateSealed response.
// 	Output: private, public, creation_out, digest_out, creation_ticket
func DecodeCreateSealed(in []byte) ([]byte, []byte, error) {
        var tpm2b_private []byte
        var tpm2b_public []byte

	// auth, tpm2b_private, tpm2b_public
        template :=  []interface{}{&tpm2b_private, &tpm2b_public}
        err := unpack(in[4:], template)
        if err != nil {
                return nil, nil, errors.New("Can't decode CreateSealed response")
        }
	// creation data
	// tpmt_tk_creation
	// digest
	return tpm2b_private, tpm2b_public, nil
}

// CreateSealed
// 	Output: public blob, private blob
func CreateSealed(rw io.ReadWriter, parent Handle, policy_digest []byte,
		  parent_password string, owner_password string,
                  to_seal []byte, pcr_nums []int, parms KeyedHashParams) ([]byte, []byte, error) {
	// Construct command
	cmd, err:= ConstructCreateSealed(parent, policy_digest,
			parent_password, owner_password,
                	to_seal, pcr_nums, parms)
	if err != nil {
		return nil, nil, errors.New("ConstructCreateSealed fails") 
	}

	// Send command
	_, err = rw.Write(cmd)
	if err != nil {
		return nil, nil, errors.New("Write Tpm fails") 
	}

	// Get response
	var resp []byte
	resp = make([]byte, 1024, 1024)
	read, err := rw.Read(resp)
        if err != nil {
                return nil, nil, errors.New("Read Tpm fails")
        }

	// Decode Response
        if read < 10 {
                return nil, nil, errors.New("Read buffer too small")
	}
	tag, size, status, err := DecodeCommandResponse(resp[0:10])
	if err != nil {
                return nil, nil, errors.New("DecodeCommandResponse fails")
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)
	if status != errSuccess {
		return nil, nil, errors.New("CreateSealed unsuccessful")
	}
	handle, nonce, err := DecodeCreateSealed(resp[10:])
        if err != nil {
                return nil, nil, errors.New("DecodeCreateSealed fails")
        }
	return handle, nonce, nil
}

// ConstructUnseal constructs a Unseal command.
func ConstructUnseal(item_handle Handle, password string, session_handle Handle) ([]byte, error)  {
	cmdHdr, err := MakeCommandHeader(tagSESSIONS, 0, cmdUnseal)
	if err != nil {
		return nil, errors.New("ConstructGetDigest failed")
	}
	// item_handle
	var tpm2b_public []byte
	handle1 := uint32(item_handle)
        out :=  []interface{}{&handle1, &tpm2b_public}
        t1, err := pack(out)
        if err != nil {
                return nil, errors.New("Can't construct CreateSealed")
        }
	t2 := CreatePasswordAuthArea(password, session_handle)
	cmd_bytes := packWithBytes(cmdHdr, append(t1, t2...))
	return cmd_bytes, nil
}

// DecodeUnseal decodes a Unseal response.
//	Output: sensitive data
func DecodeUnseal(in []byte) ([]byte, []byte, error) {
        var unsealed []byte
        var digest []byte

        template :=  []interface{}{&unsealed, &digest}
        err := unpack(in[4:], template)
        if err != nil {
                return nil, nil, errors.New("Can't decode Unseal response")
        }
	return unsealed, digest, nil
}

// Unseal
func Unseal(rw io.ReadWriter, item_handle Handle, password string, session_handle Handle,
		digest []byte) ([]byte, []byte, error) {
	// Construct command
	cmd, err:= ConstructUnseal(item_handle, password, session_handle)
	if err != nil {
		return nil, nil, errors.New("ConstructUnseal fails") 
	}

	// Send command
	_, err = rw.Write(cmd)
	if err != nil {
		return nil, nil, errors.New("Write Tpm fails") 
	}

	// Get response
	var resp []byte
	resp = make([]byte, 1024, 1024)
	read, err := rw.Read(resp)
        if err != nil {
                return nil, nil, errors.New("Read Tpm fails")
        }

	// Decode Response
        if read < 10 {
                return nil, nil, errors.New("Read buffer too small")
	}
	tag, size, status, err := DecodeCommandResponse(resp[0:10])
	if err != nil {
                return nil, nil, errors.New("DecodeCommandResponse fails")
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)
	if status != errSuccess {
		return nil, nil, errors.New("Unseal unsuccessful")
	}
	handle, nonce, err := DecodeUnseal(resp[10:])
        if err != nil {
                return nil, nil, errors.New("DecodeStartAuthSession fails")
        }
	return handle, nonce, nil
}

// ConstructQuote constructs a Quote command.
func ConstructQuote(signing_handle Handle, parent_password, owner_password string,
        	to_quote []byte, pcr_nums []int, sig_alg uint16) ([]byte, error) {
	cmdHdr, err := MakeCommandHeader(tagSESSIONS, 0, cmdQuote)
 	if err != nil {
		return nil, errors.New("ConstructQuote failed")
	}
	// TODO: no scheme or sig_alg
	// handle
 	var empty []byte
 	b1 := SetHandle(signing_handle)
	b2 ,_ := pack([]interface{}{&empty})
 	b3 := CreatePasswordAuthArea(parent_password, Handle(ordTPM_RS_PW))
 	// b4 := SetPasswordData(owner_password)
	b5 ,_ := pack([]interface{}{&sig_alg})
	b6 ,_ := pack([]interface{}{&to_quote})
 	b7 := CreateLongPcr(uint32(1), pcr_nums)
 	arg_bytes := append(b1, b2...)
 	arg_bytes = append(arg_bytes, b3...)
 	// arg_bytes = append(arg_bytes, b4...)
 	arg_bytes = append(arg_bytes, b5...)
 	arg_bytes = append(arg_bytes, b6...)
 	arg_bytes = append(arg_bytes, b7...)
	cmd_bytes := packWithBytes(cmdHdr, arg_bytes)
	return cmd_bytes, nil
}

// DecodeQuote decodes a Quote response.
//	Output: attest, signature
func DecodeQuote(in []byte) ([]byte, []byte, error) {
        var empty []byte
        var buf []byte
        var attest []byte
        var signature []byte

        template :=  []interface{}{&empty, &buf}
        err := unpack(in, template)
        if err != nil {
                return nil, nil, errors.New("Can't decode Quote response")
        }

        template =  []interface{}{&attest, &signature}
        err = unpack(buf, template)
        if err != nil {
                return nil, nil, errors.New("Can't decode Quote response")
        }
        return attest, signature, nil
}

// Quote
// 	Output: attest, sig
func Quote(rw io.ReadWriter, signing_handle Handle, parent_password string, owner_password string,
		to_quote []byte, pcr_nums []int, sig_alg uint16) ([]byte, []byte, error) {
	// Construct command
	cmd, err:= ConstructQuote(signing_handle, parent_password, owner_password, to_quote, pcr_nums, sig_alg)
	if err != nil {
		return nil, nil, errors.New("ConstructQuote fails") 
	}

	// Send command
	_, err = rw.Write(cmd)
	if err != nil {
		return nil, nil, errors.New("Write Tpm fails") 
	}

	// Get response
	var resp []byte
	resp = make([]byte, 1024, 1024)
	read, err := rw.Read(resp)
        if err != nil {
                return nil, nil, errors.New("Read Tpm fails")
        }

	// Decode Response
        if read < 10 {
                return nil, nil, errors.New("Read buffer too small")
	}
	tag, size, status, err := DecodeCommandResponse(resp[0:10])
	if err != nil {
                return nil, nil, errors.New("DecodeCommandResponse fails")
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)
	if status != errSuccess {
		return nil, nil, errors.New("Quote unsuccessful")
	}
	attest, sig, err := DecodeQuote(resp[10:])
        if err != nil {
                return nil, nil, errors.New("DecodeQuote fails")
        }
	return attest, sig, nil
}

// ConstructActivateCredential constructs a ActivateCredential command.
func ConstructActivateCredential(active_handle Handle, key_handle Handle, password string,
        credBlob []byte, secret []byte) ([]byte, error) {
	var empty []byte	
	cmdHdr, err := MakeCommandHeader(tagSESSIONS, 0, cmdActivateCredential)
 	if err != nil {
		return nil, errors.New("ConstructActivateCredential failed")
	}
 	b1 := SetHandle(active_handle)
 	b2 := SetHandle(key_handle)
	b3 ,_ := pack([]interface{}{&empty})
 	b4 := CreatePasswordAuthArea(password, Handle(ordTPM_RS_PW))
	b5 ,_ := pack([]interface{}{&credBlob, &secret})
 	arg_bytes := append(b1, b2...)
 	arg_bytes = append(arg_bytes, b3...)
 	arg_bytes = append(arg_bytes, b4...)
 	arg_bytes = append(arg_bytes, b5...)
	cmd_bytes := packWithBytes(cmdHdr, arg_bytes)
	return cmd_bytes, nil
}

// DecodeActivateCredential decodes a ActivateCredential response.
// returns certInfo
func DecodeActivateCredential(in []byte) ([]byte, error) {
	var empty []byte
        var buf []byte
        var certInfo []byte

        template :=  []interface{}{&empty, &buf}
        err := unpack(in, template)
        if err != nil {
                return nil, errors.New("Can't decode ActivateCredential response")
        }
        template =  []interface{}{&certInfo}
        err = unpack(buf, template)
        if err != nil {
                return nil, errors.New("Can't decode ActivateCredential response")
        }
	return certInfo, nil
}

// ActivateCredential
// 	Output: certinfo
func ActivateCredential(rw io.ReadWriter, active_handle Handle, key_handle Handle, password string,
		credBlob []byte, secret []byte) ([]byte, error) {
	// Construct command
	cmd, err:= ConstructActivateCredential (active_handle, key_handle, password, credBlob, secret)
	if err != nil {
		return nil, errors.New("ConstructActivateCredential fails") 
	}

	// Send command
	_, err = rw.Write(cmd)
	if err != nil {
		return nil, errors.New("Write Tpm fails") 
	}

	// Get response
	var resp []byte
	resp = make([]byte, 1024, 1024)
	read, err := rw.Read(resp)
        if err != nil {
                return nil, errors.New("Read Tpm fails")
        }

	// Decode Response
        if read < 10 {
                return nil, errors.New("Read buffer too small")
	}
	tag, size, status, err := DecodeCommandResponse(resp[0:10])
	if err != nil {
                return nil, errors.New("DecodeCommandResponse fails")
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)
	if status != errSuccess {
		return nil, errors.New("ActivateCredential unsuccessful")
	}
	cred, err := DecodeActivateCredential(resp[10:])
        if err != nil {
                return nil, errors.New("DecodeActivateCredential fails")
        }
	return cred, nil
}

// ConstructEvictControl constructs a EvictControl command.
func ConstructEvictControl(owner Handle, tmp_handle Handle, parent_password string, owner_password string,
		persistant_handle Handle) ([]byte, error) {
	cmdHdr, err := MakeCommandHeader(tagSESSIONS, 0, cmdEvictControl)
 	if err != nil {
		return nil, errors.New("ConstructEvictControl failed")
	}
 	b1 := SetHandle(owner)
 	b2 := SetHandle(tmp_handle)
	b3 := SetPasswordData(parent_password)
 	b4 := CreatePasswordAuthArea(owner_password, Handle(ordTPM_RS_PW))
 	b5 := SetHandle(persistant_handle)
 	arg_bytes := append(b1, b2...)
 	arg_bytes = append(arg_bytes, b3...)
 	arg_bytes = append(arg_bytes, b4...)
 	arg_bytes = append(arg_bytes, b5...)
	cmd_bytes := packWithBytes(cmdHdr, arg_bytes)
	return cmd_bytes, nil
}

// DecodeEvictControl decodes a EvictControl response.
func DecodeEvictControl(in []byte) (error) {
	return nil
}

// EvictControl
func EvictControl(rw io.ReadWriter, owner Handle, tmp_handle Handle, parent_password string, owner_password string,
		persistant_handle Handle) (error) {
	// Construct command
	cmd, err:= ConstructEvictControl(owner, tmp_handle, parent_password, owner_password, persistant_handle)
	if err != nil {
		return errors.New("ConstructEvictControl fails") 
	}

	// Send command
	_, err = rw.Write(cmd)
	if err != nil {
		return errors.New("Write Tpm fails") 
	}

	// Get response
	var resp []byte
	resp = make([]byte, 1024, 1024)
	read, err := rw.Read(resp)
        if err != nil {
                return errors.New("Read Tpm fails")
        }

	// Decode Response
        if read < 10 {
                return errors.New("Read buffer too small")
	}
	tag, size, status, err := DecodeCommandResponse(resp[0:10])
	if err != nil {
                return errors.New("DecodeCommandResponse fails")
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)
	if status != errSuccess {
		return errors.New("EvictControl unsuccessful")
	}
	err = DecodeEvictControl(resp[10:])
        if err != nil {
                return errors.New("DecodeEvictControl fails")
        }
	return nil
}

// ConstructSaveContext constructs a SaveContext command.
func ConstructSaveContext(handle Handle) ([]byte, error) {
	cmdHdr, err := MakeCommandHeader(tagSESSIONS, 0, cmdContextSave)
 	if err != nil {
		return nil, errors.New("ConstructSaveContext failed")
	}
 	b1 := SetHandle(handle)
	cmd_bytes := packWithBytes(cmdHdr, b1)
	return cmd_bytes, nil
}

// DecodeSaveContext constructs a SaveContext command.
func DecodeSaveContext(save_area []byte) ([]byte, error) {
	return save_area, nil
}

func SaveContext(rw io.ReadWriter, handle Handle) ([]byte, error) {
	// Construct command
	cmd, err:= ConstructSaveContext(handle)
	if err != nil {
		return nil, errors.New("ConstructSaveContext fails") 
	}

	// Send command
	_, err = rw.Write(cmd)
	if err != nil {
		return nil, errors.New("Write Tpm fails") 
	}

	// Get response
	var resp []byte
	resp = make([]byte, 1024, 1024)
	read, err := rw.Read(resp)
        if err != nil {
                return nil, errors.New("Read Tpm fails")
        }

	// Decode Response
        if read < 10 {
                return nil, errors.New("Read buffer too small")
	}
	tag, size, status, err := DecodeCommandResponse(resp[0:10])
	if err != nil {
                return nil, errors.New("DecodeCommandResponse fails")
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)
	if status != errSuccess {
		return nil, errors.New("SaveContext unsuccessful")
	}
	save_area, err := DecodeSaveContext(resp[10:])
        if err != nil {
                return nil, errors.New("DecodeSaveContext fails")
        }
	return save_area, nil
}

// LoadContext

// ConstructLoadContext constructs a LoadContext command.
func ConstructLoadContext(save_area []byte) ([]byte, error) {
	cmdHdr, err := MakeCommandHeader(tagSESSIONS, 0, cmdContextLoad)
 	if err != nil {
		return nil, errors.New("ConstructLoadContext failed")
	}
	cmd_bytes := packWithBytes(cmdHdr, save_area)
	return cmd_bytes, nil
}

// DecodeLoadContext decodes a LoadContext response.
func  DecodeLoadContext(in []byte) (Handle, error) {
	var handle uint32
        template :=  []interface{}{&handle}
        err := unpack(in, template)
        if err != nil {
                return Handle(0), errors.New("Can't decode LoadContext response")
        }
	return Handle(handle), nil
}

// LoadContext
func LoadContext(rw io.ReadWriter, save_area []byte) (Handle, error) {
	// Construct command
	cmd, err:= ConstructLoadContext(save_area)
	if err != nil {
		return Handle(0), errors.New("ConstructLoadContext fails") 
	}

	// Send command
	_, err = rw.Write(cmd)
	if err != nil {
		return Handle(0), errors.New("Write Tpm fails") 
	}

	// Get response
	var resp []byte
	resp = make([]byte, 2048, 2048)
	read, err := rw.Read(resp)
        if err != nil {
                return Handle(0), errors.New("Read Tpm fails")
        }

	// Decode Response
        if read < 10 {
                return Handle(0), errors.New("Read buffer too small")
	}
	tag, size, status, err := DecodeCommandResponse(resp[0:10])
	if err != nil {
                return Handle(0), errors.New("DecodeCommandResponse fails")
	}
	fmt.Printf("Tag: %x, size: %x, error code: %x\n", tag, size, status)
	if status != errSuccess {
		return Handle(0), errors.New("LoadContext unsuccessful")
	}
	handle, err := DecodeLoadContext(resp[10:])
        if err != nil {
                return Handle(0), errors.New("DecodeLoadContext fails")
        }
	return handle, nil
}

func UnmarshalCertifyInfo(in []byte) (*Attest, error) {
	attest := new(Attest)
	attest.magic_number = 0
	// type uint16
	// name []byte
	// data []byte
	// clock uint64
	// resetCount uint32
	// restartCount uint32
	// safe byte
	// firmwareVersion uint64
	// pcrSelect []byte
	// pcrDigest []byte
	return nil, nil
}

func ComputeQuotedValue(alg uint16, credInfo []byte) ([]byte, error) {
	if alg ==  uint16(algTPM_ALG_SHA1) {
		quoted_hash := sha1.New()
		quoted_hash.Write(credInfo)
		quoted_value := quoted_hash.Sum(nil)
    		return quoted_value, nil
	} else if alg == uint16(algTPM_ALG_SHA256) {
		quoted_hash := sha256.New()
		quoted_hash.Write(credInfo)
		quoted_value := quoted_hash.Sum(nil)
    		return quoted_value, nil
	} else {
    		return nil, errors.New("unsupported hash alg")
	}
}

func KDFA(alg uint16, key []byte, label string, contextU []byte, contextV []byte, bits int) ([]byte, error) {
	counter := uint32(0)
	bytes_left := (bits + 7) / 8;
	var out []byte
	for ; bytes_left > 0 ; {
		counter = counter + 1
		if alg == algTPM_ALG_SHA1 {
			mac := hmac.New(sha1.New, key)
			// copy counter (big Endian), label, contextU, contextV, bits (big Endian)
			outa,_ := pack([]interface{}{&counter})
			var arr [32]byte
			copy(arr[0:], label)
			arr[len(label)] = 0
			outc := append(contextU, contextV...)
			u_bits := uint32(bits)
			outd,_ := pack([]interface{}{&u_bits})
			in := append(outa, append(arr[0:len(label)+1], append(outc, outd...)...)...)
			mac.Write(in)
			out = append(out, mac.Sum(nil)...)
			bytes_left -= 20
		} else if alg == algTPM_ALG_SHA256 {
			mac := hmac.New(sha256.New, key)
			// copy counter (big Endian), label, contextU, contextV, bits (big Endian)
			outa, _ := pack([]interface{}{&counter})
			var arr [32]byte
			copy(arr[0:], label)
			arr[len(label)] = 0
			outc := append(contextU, contextV...)
			u_bits := uint32(bits)
			outd,_ := pack([]interface{}{&u_bits})
			in := append(outa, append(arr[0:len(label)+1], append(outc, outd...)...)...)
			mac.Write(in)
			out = append(out, mac.Sum(nil)...)
			bytes_left -= 32
		} else {
			return nil, errors.New("Unsupported key hmac alg")
		}
	}
	return out, nil
}

func ComputePcrDigest(alg uint16, in []byte) ([]byte, error) {
	// in should just be a sequence of digest values
	return ComputeQuotedValue(alg, in)
}

func PrintRsaPublicKey(key *TpmRsaPublicKey) {
	fmt.Printf("enc_alg : %x\n", key.rsa_params.enc_alg)
	fmt.Printf("hash_alg : %x\n", key.rsa_params.hash_alg)
	fmt.Printf("attributes : %x\n", key.rsa_params.attributes)
	fmt.Printf("auth_policy : %x\n", key.rsa_params.auth_policy)
	fmt.Printf("symalg : %x\n", key.rsa_params.symalg)
	fmt.Printf("sym_sz : %x\n", key.rsa_params.sym_sz)
	fmt.Printf("mode : %x\n", key.rsa_params.mode)
	fmt.Printf("scheme : %x\n", key.rsa_params.scheme)
	fmt.Printf("size modulus : %x\n", key.rsa_params.mod_sz)
	fmt.Printf("modulus : %x\n", key.rsa_params.modulus)
	fmt.Printf("name : %x\n", key.name)
	fmt.Printf("qualified_name : %x\n", key.qualified_name)
}

// Note: Only Rsa keys for now
func GetRsaPublicKeyFromBlob(in []byte) (*TpmRsaPublicKey, error) {
	key := new(TpmRsaPublicKey)
	var  out_public []byte

	template :=  []interface{}{&out_public}
        err := unpack(in, template)
        if err != nil {
                return nil, errors.New("Can't decode response")
        }
	rsaParams, err := DecodeRsaArea(out_public)
        if err != nil {
                return nil, errors.New("Can't decode Rsa Area")
        }
	key.rsa_params = rsaParams

	template =  []interface{}{&key.name, &key.qualified_name}
        err = unpack(in[len(out_public) + 2:], template)
        if err != nil {
                return nil, errors.New("Can't decode response")
        }

	return key, nil
}

//	Return: out_hmac, output_data
func EncryptDataWithCredential(encrypt_flag bool, hash_alg_id uint16,
		unmarshaled_credential []byte, input_data []byte, in_hmac []byte) ([]byte, []byte, error) {
	return nil, nil, nil
}

//	1. Generate Seed
//	2. encrypted_secret= E(protector_key, seed || "IDENTITY")
//	3. symKey ≔ KDFa (ekNameAlg, seed, “STORAGE”, name, NULL , bits)
//	4. encIdentity ≔ AesCFB(symKey, 0, credential)
//	5. HMACkey ≔ KDFa (ekNameAlg, seed, “INTEGRITY”, NULL, NULL, bits)
//	6. outerHMAC ≔ HMAC(HMACkey, encIdentity || Name)
//
//	Return (all []byte)
//		encrypted_secret
//		encIdentity
//		integrityHmac
func MakeCredential(endorsement_blob []byte, hash_alg_id uint16,
		unmarshaled_credential []byte, unmarshaled_name []byte) ([]byte, []byte, []byte, error) {
	var a [20]byte
	copy(a[:], "IDENTITY")
	a[len("IDENTITY")] = 0
	rsaKeyParams, err := GetRsaPublicKeyFromBlob(endorsement_blob)
	if err !=nil {
		return nil, nil, nil, err
	}
	fmt.Printf("rsaKeyParams: %x\n", rsaKeyParams)
	m := new(big.Int)
	m.SetBytes(rsaKeyParams.rsa_params.modulus[0:len(rsaKeyParams.rsa_params.modulus)])
	public := rsa.PublicKey{m, int(rsaKeyParams.rsa_params.exp)}
	var encrypted_secret []byte
	if hash_alg_id == uint16(algTPM_ALG_SHA1) {
		encrypted_secret, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, &public, unmarshaled_credential,
			a[0:len("IDENTITY")+1])
	} else if hash_alg_id == uint16(algTPM_ALG_SHA256) {
		encrypted_secret, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, &public, unmarshaled_credential,
			a[0:len("IDENTITY")+1])
	} else {
		return nil, nil, nil, errors.New("Unsupported hash alg") 
	}
	fmt.Printf("encrypted_secret    : %x\n", encrypted_secret)

	// replace with RAND_bytes
	seed := []byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	// var seed []byte
	// rand.Read(seed[0:16]);

	var symKey []byte
	iv := []byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	if hash_alg_id == uint16(algTPM_ALG_SHA1) {
		symKey, err = KDFA(uint16(algTPM_ALG_SHA1), seed, "STORAGE", nil, nil, 128)
		if err !=nil {
			return nil, nil, nil, err
		}
	} else if hash_alg_id == uint16(algTPM_ALG_SHA256) {
		symKey, err = KDFA(uint16(algTPM_ALG_SHA256), seed, "STORAGE", nil, nil, 128)
		if err !=nil {
			return nil, nil, nil, err
		}
	} else {
			return nil, nil, nil, errors.New("Unsupported hash alg") 
	}
	fmt.Printf("symKey: %x\n", symKey)
	block, err := aes.NewCipher(symKey)
	if err !=nil {
		return nil, nil, nil, err
	}
	fmt.Printf("         credential: %x\n", unmarshaled_credential)
	encIdentity := make([]byte, len(unmarshaled_credential))
	copy(encIdentity, unmarshaled_credential)
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(encIdentity, unmarshaled_credential)
	fmt.Printf("encIdentity: %x\n", encIdentity)

	cfbdec := cipher.NewCFBDecrypter(block, iv)
	decrypted_credential := make([]byte, len(unmarshaled_credential))
	cfbdec.XORKeyStream(decrypted_credential, encIdentity)
	fmt.Printf("decrypted credential: %x\n", decrypted_credential)

	hmacKey, err := KDFA(uint16(algTPM_ALG_SHA1), seed, "INTEGRITY", nil, nil, 128)
	if err !=nil {
		return nil, nil, nil, err
	}
	fmt.Printf("hmacKey: %x\n", hmacKey)

	var hmac_bytes []byte	
	if hash_alg_id == uint16(algTPM_ALG_SHA1) {
		mac := hmac.New(sha1.New, hmacKey)
		mac.Write(append(encIdentity, unmarshaled_name...))
		hmac_bytes = mac.Sum(nil)
	} else if hash_alg_id == uint16(algTPM_ALG_SHA256) {
		mac := hmac.New(sha256.New, hmacKey)
		mac.Write(append(encIdentity, unmarshaled_name...))
		hmac_bytes = mac.Sum(nil)
	} else {
		return nil, nil, nil, errors.New("Unsupported has alg") 
	}
	fmt.Printf("hmac                : %x\n", hmac_bytes)
	return encrypted_secret, encIdentity, hmac_bytes, nil
}

// Input: Der encoded endorsement key and handles
// Returns der encoded program private key, CertRequestMessage
func ConstructClientRequest(rw io.ReadWriter, der_endorsement_cert []byte, quote_handle Handle,
		parent_pw string, owner_pw string, program_name string) ([]byte, *ProgramCertRequestMessage, error) {
	// Generate Program Key.
	programPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	der_program_key := x509.MarshalPKCS1PrivateKey(programPrivateKey)
	
	// Generate Request
	request := new(ProgramCertRequestMessage)
	request.EndorsementCertBlob = der_endorsement_cert
	req_id := "001"
	modulus_bits := int32(2048)
	key_type := "RSA"
	request.RequestId = &req_id
        request.ProgramKey.ProgramName = &program_name
        request.ProgramKey.ProgramKeyType = &key_type
        request.ProgramKey.ProgramBitModulusSize = &modulus_bits
        // request.ProgramKey.ProgramKeyExponent = 0x010001
        // request.ProgramKey.ProgramKeyModulus
	serialized_program_key := request.ProgramKey.String();
	sha256Hash := sha256.New()
	sha256Hash.Write([]byte(serialized_program_key))
	hashed_program_key := sha256Hash.Sum(nil)
	fmt.Printf("ProgramKey: %s\n", serialized_program_key)
	fmt.Printf("Hashed req: %s\n", hashed_program_key)
	key_blob, name, _, err := ReadPublic(rw, quote_handle)
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("Quote key blob: %x\n", key_blob)
	fmt.Printf("Name: %x\n", name)

	sig_alg := uint16(algTPM_ALG_RSASSA) // Check!
	attest, sig, err := Quote(rw, quote_handle, parent_pw, owner_pw, hashed_program_key,
		[]int{7}, sig_alg)
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("Attest: %x\n", attest)
	fmt.Printf("Sig: %x\n", sig)

	// Quote key info.
        request.Cred.Name = name
        // request.Cred.Properties
        // request.Cred.PublicKeyMessage.KeyName
        // request.Cred.PublicKeyMessage.KeyType
        // request.Cred.PublicKeyMessage.BitModulusSize
        // request.Cred.PublicKeyMessage.Modulus
        // request.ActiveSignAlg
        // request.ActiveSignBitSize
        // request.ActiveSignHashAlg

        request.QuotedBlob = attest
        request.ActiveSignature = sig
	return der_program_key, request, nil
}

// Input: Der encoded policy private key
func ConstructServerResponse(der_policy_key []byte,
	     signing_instructions_message SigningInstructionsMessage,
	     request_message ProgramCertRequestMessage) (*ProgramCertResponseMessage, error) {
	program_key, err := x509. ParsePKCS1PrivateKey(der_policy_key)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Key: %x\n", program_key)
	// endorsement_cert, err := x509.ParseCertificate(der_endorsement_cert)
	// ParseCertificates(asn1Data []byte) ([]*Certificate, error)
	// CreateCertificate(rand io.Reader, template, parent *Certificate, pub, priv interface{})
	// ParseCertificate(asn1Data []byte) (*Certificate, error)
	// (c *Certificate) Verify(opts VerifyOptions) (chains [][]*Certificate, err error)
	// signing_instructions_message.GetIssuer(), GetDuration(), GetPurpose()
	// signing_instructions_message.GetSignAlg(), GetHashAlg(), GetIsCA(), GetCanSign()
	// Hash request: request.program_key().DebugString();
	// Decode attest: UnmarshalCertifyInfo(quote_struct_size, quote_struct, &attested_quote)
	// attested_quote.magic !=  TpmMagicConstant?
	// PCR's valid?
	// Get quote key: request.cred().public_key().rsa_key().modulus().size()
	// RSA_public_encrypt(request.active_signature().size(),
	//	(const byte*)request.active_signature().data(), decrypted_quote,active_key, RSA_NO_PADDING);
	// Check hash of request: memcmp(attested_quote.extraData.buffer, program_key_quoted_hash,
	//	attested_quote.extraData.size)
	// Compare signature and computed hash memcmp(signed_quote_hash,
	//	decrypted_quote + size_active_out - SizeHash(hash_alg_id), SizeHash(hash_alg_id))

	// Generate credential
	// encrypted_secret, encIdentity, integrityHmac, err := MakeCredential(endorsement_blob []byte,
	// hash_alg_id uint16, unmarshaled_credential []byte, unmarshaled_name []byte)
	return nil, nil
}

// Output is der encoded Program Cert
func ClientDecodeServerResponse(rw io.ReadWriter, endorsement_handle Handle, quote_handle Handle,
		server_response_message ProgramCertResponseMessage) ([]byte, error) {
	// certInfo, err := ActivateCredential(rw, active_handle, key_handle, password, credBlob, secret)
	// Decrypt cert.
	// _, out, err :=  EncryptDataWithCredential(encrypt_flag bool, hash_alg_id,
        //        unmarshaled_credential, input_data, in_hmac)
	return nil, nil
}
