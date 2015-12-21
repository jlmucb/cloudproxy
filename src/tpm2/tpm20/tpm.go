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
	"encoding/hex"
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

// Fill Rsa key structure for public blob
// Note: Only Rsa keys for now
func GetPublicKeyFromBlob(in []byte) (*RsaKey, error) {
	key := new(RsaKey)
	return key, nil
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
func CreatePasswordAuthArea(password string) ([]byte) {
	owner_str := SetHandle(Handle(ordTPM_RS_PW))
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
func CreateKeyedHash(parms KeyedHashParams) ([]byte) {
	// 0 (uint16)
	// type
	// attributes
	// auth
	// scheme
	return nil
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

func ComputePcrDigest(alg uint16, in []byte) ([]byte, error) {
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
	x, err:= ConstructFlushContext(handle)
	if err != nil {
		return errors.New("ConstructFlushContext fails") 
	}

	// Send command
	_, err = rw.Write(x)
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
	out := []interface{}{&num, &pcrs}
	x, _ := packWithHeader(cmdHdr, out)
	return x, nil
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
	x, _ := packWithHeader(cmdHdr, nil)
	return x, nil
}

// DecodeReadClock decodes a ReadClock response.
func DecodeReadClock(in []byte) (uint64, uint64, error) {
        var current_time, current_clock uint64

        out :=  []interface{}{&current_time, &current_clock}
        err := unpack(in, out)
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
	x, _ := packWithHeader(cmdHdr, cap_bytes)
	return x, nil
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
	b3 := CreatePasswordAuthArea(parent_password)
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
	cmd_bytes, _ := packWithHeader(cmdHdr, nil)
	return append(cmd_bytes, arg_bytes...), nil
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
	x, err:= ConstructCreatePrimary(uint32(owner), pcr_nums, parent_password,
		owner_password, parms)
	if err != nil {
		fmt.Printf("MakeCommandHeader failed %s\n", err)
		return Handle(0), nil, err
	}

	// Send command
	_, err = rw.Write(x)
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
	x, _ := packWithHeader(cmdHdr, num_bytes)
	return x, nil
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
 	b3 := CreatePasswordAuthArea(parent_password)
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
	cmd_bytes, _ := packWithHeader(cmdHdr, nil)
	return append(cmd_bytes, arg_bytes...), nil
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
	x, err:= ConstructCreateKey(uint32(owner), pcr_nums, parent_password,
                owner_password, parms)
	if err != nil {
		fmt.Printf("MakeCommandHeader failed %s\n", err)
		return nil, nil, err
	}

	// Send command
	_, err = rw.Write(x)
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
func ConstructLoad(parentHandle Handle, parentAuth string,
             public_blob []byte, private_blob []byte) ([]byte, error) {
	cmdHdr, err := MakeCommandHeader(tagSESSIONS, 0, cmdLoad)
	if err != nil {
		return nil, errors.New("ConstructLoad failed")
	}
	var empty []byte
	b1 := SetHandle(parentHandle)
	b2,_ := pack([]interface{}{&empty})
	b3 := CreatePasswordAuthArea("")
	b4 := SetPasswordData(parentAuth)
	x, _ := packWithHeader(cmdHdr, nil)
	// private, public
	b5,_ := pack([]interface{}{&private_blob, &public_blob})
	cmd_bytes := append(x, b1...)
	cmd_bytes = append(cmd_bytes, b2...)
	cmd_bytes = append(cmd_bytes, b3...)
	cmd_bytes = append(cmd_bytes, b4...)
	cmd_bytes = append(cmd_bytes, b5...)
	return b5, nil
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
func Load(rw io.ReadWriter, parentHandle Handle, parentAuth string,
	     public_blob []byte, private_blob []byte) (Handle, []byte, error) {

	// Construct command
	x, err:= ConstructLoad(parentHandle, parentAuth, public_blob, private_blob)
	if err != nil {
		fmt.Printf("MakeCommandHeader failed %s\n", err)
		return Handle(0), nil, err
	}

	// Send command
	_, err = rw.Write(x)
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
// PolicyPcr command: 80010000001a0000017f 03000000 0000 00000001 000403800000
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
	cmd, _ := packWithHeader(cmdHdr, nil)
	cmd = append(cmd, append(b1, b2...)...)
	return cmd, nil
}

// ConstructPolicyPassword constructs a PolicyPassword command.
// Command: 80010000000e0000018c03000000
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
	cmd, _ := packWithHeader(cmdHdr, nil)
	cmd = append(cmd, b1...)
	return cmd, nil
}

// PolicyPassword
func PolicyPassword(rw io.ReadWriter, handle Handle) (error) {
	// Construct command
	x, err:= ConstructPolicyPassword(handle)
	if err != nil {
		fmt.Printf("MakeCommandHeader failed %s\n", err)
		return err
	}

	// Send command
	_, err = rw.Write(x)
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
// Command: 80010000000e0000018903000000
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
	cmd, _ := packWithHeader(cmdHdr, nil)
	cmd = append(cmd, b1...)
	return cmd, nil
}

// DecodePolicyGetDigest decodes a PolicyGetDigest response.
func DecodePolicyGetDigest(in []byte) ([]byte, error) {
        var digest []byte

        out :=  []interface{}{&digest}
        err := unpack(in, out)
        if err != nil {
                return nil, errors.New("Can't decode Load response")
        }
        return digest, nil
}

// PolicyGetDigest
//	Output: digest
func PolicyGetDigest(rw io.ReadWriter, handle Handle) ([]byte, error) {
	// Construct command
	cmd, err:= ConstructPolicyGetDigest(handle)
	if err != nil {
		fmt.Printf("MakeCommandHeader failed %s\n", err)
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
// Command: 80010000002b00000176400000074000000700100000000000000000000000000000000000000100100004
func ConstructStartAuthSession() ([]byte, error) {
	// tpm_key
	// bind (TPM_RH_NULL)
	// noncecaller
	// encrypted secret (salt)
	// TPM_SE
	// TPM_SYM_DEF
	// Alg hash
	return nil, nil
}

// DecodeStartAuthSession decodes a StartAuthSession response.
//	Output: session_handle, nonce
// Response: 800100000020000000000300000000106cf0c90c419ce1a96d5205eb870ec527
func DecodeStartAuthSession(in []byte) ([]byte, error) {
	return nil, nil
}

// StartAuthSession
func StartAuthSession(rw io.ReadWriter) (Handle, error) {
	return Handle(0), nil
}

// ConstructCreateSealed constructs a CreateSealed command.
// Command: 80020000006900000153800000000000000d40000009000001000401020304001800040102030400100102030405060708090a0b0c0d0e0f100022000800040000001200140debb4cc9d2158cf7051a19ca24b31e35d53b64d00100000000000000001000403800000
func ConstructCreateSealed(parent Handle, policy_digest []byte, parent_password string,
        	to_seal []byte, pcr_selection []byte, parms KeyedHashParams) ([]byte, error) {
	// parent handle
	// auth (0)
	// pasword auth area
	// Sensitive area
	// keyed hash template
	// outside info
	// pcr long
	return nil, nil
}

// DecodeCreateSealed decodes a CreateSealed response.
// 	Output: private, public, creation_out, digest_out, creation_ticket
func DecodeCreateSealed(in []byte) ([]byte, []byte, error) {
	return nil, nil, nil
}

// CreateSealed
// 	Output: public blob, private blob
func CreateSealed(rw io.ReadWriter, 
		parent Handle, policy_digest []byte, parent_password string, 
		to_seal []byte, pcr_selection []byte, int_alg uint16,
        	create_flags uint32, sym_alg uint16, sym_key_size_bits uint16,
        	sym_mode uint16, sig_scheme uint16, modulus_size_bits uint16,
		exp uint32) ([]byte, []byte, error) {
	return nil, nil, nil
}

// ConstructUnseal constructs a Unseal command.
// Command: 80020000001f0000015e800000010000000d03000000000001000401020304
func ConstructUnseal(item_handle Handle, password string, session_handle Handle,
        	attributes []byte, digest []byte) ([]byte, error) {
	// item_handle
	return nil, nil
}

// DecodeUnseal decodes a Unseal response.
//	Output: sensitive data
// Resp: 800200000035000000000000001200100102030405060708090a0b0c0d0e0f100010ea78d080f9f77d9d85e1f80350247ecb010000
func DecodeUnseal(in []byte) ([]byte, error) {
	return nil, nil
}

// Unseal
func Unseal(rw io.ReadWriter, item_handle Handle, password string, session_handle Handle,
	attributes []byte, digest []byte) ([]byte, error) {
	return nil, nil
}

// ConstructQuote constructs a Quote command.
// Command: 80020000003d00000158800000010000000d4000000900000100040102030400100102030405060708090a0b0c0d0e0f10001000000001000403800000
func ConstructQuote(isigning_handle Handle, password string,
        	to_quote []byte, scheme uint16, pcr []byte, sig_alg uint16,
        	hash_alg uint16) ([]byte, error) {
	// handle
	// qualifying data
	// sig scheme
	// long pcr selection
	return nil, nil
}

// DecodeQuote decodes a Quote response.
//	Output: attest, signature
// Response: a80020000010400000000000000f10069ff5443478018001600047705bde86e3780577632421d34e5db4759667c8900100102030405060708090a0b0c0d0e0f1000000000000fe8f99cf4968c1d6e516100eb40a3278641a1c6000000010004038000000014ae2edb7e23d7e8f58daa87af87775993a42672250014000400804e49bb73712bc6acca4778005741b586ee6da2c98fe4dd1a3babdd9dd58c2d6fed9441a5bfb3c07ae0c7a5f2aff3d46b97429cff515caa12726fec6021b439c9856ebdd2f006b9159b5bfcbb8ca16c6a8f4a5953669d6af769593c00249e240f5009735b03abff38917de1c43bfdcc7a488fa6474c1011d3f399939e033930bb0000010000
func DecodeQuote(in []byte) ([]byte, []byte, error) {
        var attest []byte
        var signature []byte

        out :=  []interface{}{&attest, &signature}
        err := unpack(in, out)
        if err != nil {
                return nil, nil, errors.New("Can't decode Quote response")
        }
        return attest, signature, nil
}

// Quote
// 	Output: attest, sig
func Quote(rw io.ReadWriter, signing_handle Handle, password string,
		to_quote []byte, scheme uint16, pcr []byte, sig_alg uint16,
		hash_alg uint16) ([]byte, []byte, error) {
	return nil, nil, nil
}

// ConstructActivateCredential constructs a ActivateCredential command.
// Command: 800200000168000001478000000280000000000000164000000900000100040102030440000009000001000000380020a2b634475ae0cfccff45d273f173cb4c74089167c94ed4666fa41a0039b71ad6956316cbb65c1ac71225c204d9f752fa62a84c70b51701007d9fec0ddff9c8e27904913f498aa20416e66e4a91eeb263d1a7badd7bd0043b4f2e165018d21e892359856cd93b45a983606e3482b029796659266f01277c944500bda57a5442d670173093307377783fd94aaf481bbdde1914720fc7f41637ff66593c50ce72626bc6e5edfa6e532c446faa3af1279f68d84edaa7386d97229be8edf74fc33e74e2f0f4b7a1ec985b42463fbf387ecc268b3a3a45c66968113ab0ed0d3573a9076eebe3d45efbc12c970465cf80af155434d8b0eb377a50942a742f86a0fa93c29bd0c37e8ac18c2f6b63558ba03df7bc5f80be70e504203b2b55c243794e7fc4cdb817e2da0796e088ca408a3c5d95abb32fa6dfddd4101f
func ConstructActivateCredential(active_handle Handle, key_handle Handle,
        credBlob []byte, secret []byte) ([]byte, error) {
	// active_handle
	// key_handle
	// cred_blob
	// secret
	return nil, nil
}

// DecodeActivateCredential decodes a ActivateCredential response.
// returns certInfo
// Response: 80020000002e000000000000001600140102030405060708090a0b0c0d0e0f101112131400000100000000010000
func DecodeActivateCredential(in []byte) ([]byte, error) {
	return nil, nil
}

// ActivateCredential
// 	Output: certinfo
func ActivateCredential(rw io.ReadWriter, active_handle Handle, key_handle Handle,
		active_password string, key_password string) ([]byte, []byte, error) {
	return nil, nil, nil
}

// ConstructEvictControl constructs a EvictControl command.
// Command: 800200000023 00000120 40000001 810003e8 0000 000940000009000001 0000810003e8
func ConstructEvictControl(tmp_handle Handle, password string, persistant_handle Handle) ([]byte, error) {
	// owner
	// loaded object handle
	// auth 0
	// auth
	// persistant handle
	return nil, nil
}

// DecodeEvictControl decodes a EvictControl response.
// Response: 80020000001300000000000000000000010000
func DecodeEvictControl(in []byte) (error) {
	return nil
}

// EvictControl
func EvictControl(rw io.ReadWriter, tmp_handle Handle, password string,
		persistant_handle Handle) (error) {
	return nil
}

// ConstructSaveContext constructs a SaveContext command.
// command: 80010000000e0000016280000000
func ConstructSaveContext(handle Handle, save_area []byte) ([]byte, error) {
	// handle
	return nil, nil
}

// DecodeSaveContext constructs a SaveContext command.
// output contest
// 8001000003a60000000000000000000000268000000040000001038a00202280de0e478f25261abb7b96dc2f74f3be2b005bc4ad02a595074660aa0560a2b719fc2865b391dba8a7cb0d27eec7b30a5608c8b35bd42c8308cadc5c900f51f70cba9eebc0f63a86294c5f90dd8dcb64d08494dcb82571683090a5ba37398ff03e801384b21b7d2f5f0d50d96ed21ad49b79df200edab3427f59c574918c54385ee346a946e21430315ce00af2edf615cbcef035691edf723d20c6adc7ca5a98cb78c9e72bc7edd604dd04943b0bd7ec77b8236ec3fd64524d6dcd1fc6436e0e07dff24422ec3e51153000cdff8e4e65013d331941ce72b49bf4a454a394c4fe821ab6d7caecaa8d48081ba5865d76c631acfd301b9ef582d2dd9c54c380f44a849ff5fc182bc81071f32dea85f4016b74434ee2979a93d2e5ff51e061c8694d3e953c1d18ca714c72e4196dd6b82371724580f367780ec11d1a6ffa7a7485d6d503769896fba02d61ceb901cca0c2fc27689cd62b384ea28c0318fed3cd19c22dbef6ac08e49347b90227f94c3a544d7846ce93581c7ee76da5535651056b4dc2d669323684fc0ac93bdf44c3c2246f3bdb53f0b8df9d0b2bf39d85dbd7a1b2b76154474bf745664806919a13689b83d84780079d227f5d4021532097b0b4152661f6095b789259c968966e89e4ec272b3b54413bd0fabf9bcf241d78a6fbe61ba326d8f91ee012d5a31e15f46a0a45a2be0482f714c027df0c957806f8697a69d72ef7e4c2dbde2430f173e7a66b2f8fbab8e8b97fbecef8b2bdcddb572636aded2fb4f77f10009dd71bcf70264526f89bc3723fee3ba423cb1f2ba96c0080618667a2d358c2361c37fb2f72c5a02f4e4f9cdbf1f685651e0710b4d0da70b89ebca400c0f58b897b9c93eb8e840bdbc9f5aa13edd6803d3321d2f3672b73300d6d8629950264d9d5f404cf63f97f7f511df2f1aa58e8f1f80b6fbd75c3b7dd45321e1e4c964af1dc8014d9ded585493a905a91d5ec038cfe854fb33a99667b89789078fdf12841737789545a7e9f4323cbb27c3c9a9148fb567b4c9dd026f6be97a78d0ddbc7f86752b8369ed72ec82350a45215f4aaa24ee3d85cff8bd2c6b5071420ffc14f0b6650d5a3b1335e26faa9552f98a7c02e43babdd0ca23f78222af6454e169fbef9fd35b97d837c3fe51d7a0b2f0ac27912d1eb249f5b7d2194f32464dc24d3f29c91c2dc524ef4fcbe762194ceb3383dcd3baffd03e2ff40898e55819606db26d988f1d67fdf3875d77019a3a0dc3284b9e0f8c18f89d87f178c9363de081e4
func DecodeSaveContext(handle Handle, save_area []byte) ([]byte, error) {
	// context
	return nil, nil
}

func SaveContext(rw io.ReadWriter, handle Handle, save_area []byte) (error) {
	return nil
}

// LoadContext

// ConstructLoadContext constructs a LoadContext command.
// command: 8001000003a60000016100000000000000268000000040000001038a00202280de0e478f25261abb7b96dc2f74f3be2b005bc4ad02a595074660aa0560a2b719fc2865b391dba8a7cb0d27eec7b30a5608c8b35bd42c8308cadc5c900f51f70cba9eebc0f63a86294c5f90dd8dcb64d08494dcb82571683090a5ba37398ff03e801384b21b7d2f5f0d50d96ed21ad49b79df200edab3427f59c574918c54385ee346a946e21430315ce00af2edf615cbcef035691edf723d20c6adc7ca5a98cb78c9e72bc7edd604dd04943b0bd7ec77b8236ec3fd64524d6dcd1fc6436e0e07dff24422ec3e51153000cdff8e4e65013d331941ce72b49bf4a454a394c4fe821ab6d7caecaa8d48081ba5865d76c631acfd301b9ef582d2dd9c54c380f44a849ff5fc182bc81071f32dea85f4016b74434ee2979a93d2e5ff51e061c8694d3e953c1d18ca714c72e4196dd6b82371724580f367780ec11d1a6ffa7a7485d6d503769896fba02d61ceb901cca0c2fc27689cd62b384ea28c0318fed3cd19c22dbef6ac08e49347b90227f94c3a544d7846ce93581c7ee76da5535651056b4dc2d669323684fc0ac93bdf44c3c2246f3bdb53f0b8df9d0b2bf39d85dbd7a1b2b76154474bf745664806919a13689b83d84780079d227f5d4021532097b0b4152661f6095b789259c968966e89e4ec272b3b54413bd0fabf9bcf241d78a6fbe61ba326d8f91ee012d5a31e15f46a0a45a2be0482f714c027df0c957806f8697a69d72ef7e4c2dbde2430f173e7a66b2f8fbab8e8b97fbecef8b2bdcddb572636aded2fb4f77f10009dd71bcf70264526f89bc3723fee3ba423cb1f2ba96c0080618667a2d358c2361c37fb2f72c5a02f4e4f9cdbf1f685651e0710b4d0da70b89ebca400c0f58b897b9c93eb8e840bdbc9f5aa13edd6803d3321d2f3672b73300d6d8629950264d9d5f404cf63f97f7f511df2f1aa58e8f1f80b6fbd75c3b7dd45321e1e4c964af1dc8014d9ded585493a905a91d5ec038cfe854fb33a99667b89789078fdf12841737789545a7e9f4323cbb27c3c9a9148fb567b4c9dd026f6be97a78d0ddbc7f86752b8369ed72ec82350a45215f4aaa24ee3d85cff8bd2c6b5071420ffc14f0b6650d5a3b1335e26faa9552f98a7c02e43babdd0ca23f78222af6454e169fbef9fd35b97d837c3fe51d7a0b2f0ac27912d1eb249f5b7d2194f32464dc24d3f29c91c2dc524ef4fcbe762194ceb3383dcd3baffd03e2ff40898e55819606db26d988f1d67fdf3875d77019a3a0dc3284b9e0f8c18f89d87f178c9363de081e4
func ConstructLoadContext(save_area []byte) ([]byte, error) {
	// context
	return nil, nil
}

// DecodeLoadContext decodes a LoadContext response.
// 80010000000e0000000080000000
func  DecodeLoadContext(in []byte) (Handle, error) {
	// handle
	return Handle(0), nil
}

// LoadContext
func LoadContext(rw io.ReadWriter, save_area []byte) (Handle, error) {
	return Handle(0), nil
}

/*
bool ComputeQuotedValue(TPM_ALG_ID alg, int credInfo_size, byte* credInfo,
                        int* size_quoted, byte* quoted)

ComputeMakeCredentialData()
 */
