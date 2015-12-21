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
	// 0 (uint16)
	// type
	// attributes
	// auth
	// scheme
	// 0 (uinque)
	var empty []byte
	template1 := []interface{}{&empty, &parms.type_alg, &parms.hash_alg, &parms.attributes,
		&parms.auth_policy, &parms.scheme, &empty}
	t1, err := pack(template1)
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
	cmd, _ := packWithHeader(cmdHdr, nil)
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
	b3 := CreatePasswordAuthArea("", Handle(ordTPM_RS_PW))
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
	cmd, err:= ConstructLoad(parentHandle, parentAuth, public_blob, private_blob)
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
	cmd, _ := packWithHeader(cmdHdr, nil)
	cmd = append(cmd, append(b1, b2...)...)
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
	cmd, _ := packWithHeader(cmdHdr, nil)
	cmd = append(cmd, b1...)
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
	cmd_bytes, _ := packWithHeader(cmdHdr, nil)
	return append(cmd_bytes, arg_bytes...), nil
	return nil, nil
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
func ConstructCreateSealed(parent Handle, policy_digest []byte, parent_password string, owner_password string,
        	to_seal []byte, pcr_nums []int, parms KeyedHashParams) ([]byte, error) {
	// parent handle
	// auth (0)
	// pasword auth area
	// Sensitive area
	// keyed hash template
	// outside info
	// pcr long
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
 	b5 := CreateKeyedHashParams(parms)
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

// DecodeCreateSealed decodes a CreateSealed response.
// 	Output: private, public, creation_out, digest_out, creation_ticket
func DecodeCreateSealed(in []byte) ([]byte, []byte, error) {
        var tpm2b_private []byte
        var tpm2b_public []byte

	// auth?
	// tpm2b_private
	// tpm2b_public
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
func CreateSealed(rw io.ReadWriter, parent Handle, policy_digest []byte, parent_password string, owner_password string,
                to_seal []byte, pcr_nums []int, parms KeyedHashParams) ([]byte, []byte, error) {
	// Construct command
	cmd, err:= ConstructCreateSealed(parent, policy_digest, parent_password, owner_password,
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
func ConstructUnseal(item_handle Handle, password string, session_handle Handle,
        	digest []byte) ([]byte, error) {
	cmdHdr, err := MakeCommandHeader(tagNO_SESSIONS, 0, cmdUnseal)
	if err != nil {
		return nil, errors.New("ConstructGetDigest failed")
	}
	cmd, _ := packWithHeader(cmdHdr, nil)
	// item_handle
	var tpm2b_public []byte
	handle1 := uint32(item_handle)
        out :=  []interface{}{&handle1, &tpm2b_public}
        t1, err := pack(out)
        if err != nil {
                return nil, errors.New("Can't construct CreateSealed")
        }
	t2 := CreatePasswordAuthArea(password, session_handle)
	t3 := SetHandle(session_handle)
	return append(cmd, append(t1, append(t2, t3...)...)...), nil
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
	cmd, err:= ConstructUnseal(item_handle, password, session_handle, digest)
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
        	to_quote []byte, pcr_nums []int, scheme uint16, sig_alg uint16) ([]byte, error) {
	var qualifying_data []byte
	
	cmdHdr, err := MakeCommandHeader(tagSESSIONS, 0, cmdQuote)
 	if err != nil {
		return nil, errors.New("ConstructQuote failed")
	}
	// handle
 	var empty []byte
 	b1 := SetHandle(signing_handle)
	b2 ,_ := pack([]interface{}{&empty})
 	b3 := CreatePasswordAuthArea(parent_password, Handle(ordTPM_RS_PW))
 	b4 := SetPasswordData(owner_password)
	b5 ,_ := pack([]interface{}{&qualifying_data})
	b6 ,_ := pack([]interface{}{&scheme, &sig_alg})
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

// DecodeQuote decodes a Quote response.
//	Output: attest, signature
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
func Quote(rw io.ReadWriter, signing_handle Handle, parent_password string, owner_password string,
		to_quote []byte, pcr_nums []int, scheme uint16, sig_alg uint16) ([]byte, []byte, error) {
	// Construct command
	cmd, err:= ConstructQuote(signing_handle, parent_password, owner_password, to_quote, pcr_nums, scheme, sig_alg)
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
	cmd_bytes, _ := packWithHeader(cmdHdr, nil)
	return append(cmd_bytes, arg_bytes...), nil
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
	cmd_bytes, _ := packWithHeader(cmdHdr, nil)
	return append(cmd_bytes, arg_bytes...), nil
	return nil, nil
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
	cmd, err := packWithHeader(cmdHdr,nil)	
 	if err != nil {
		return nil, errors.New("ConstructSaveContext failed")
	}
 	b1 := SetHandle(handle)
	return append(cmd, b1...), nil
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
	cmd, err := packWithHeader(cmdHdr, nil)
        if err != nil {
                return nil, errors.New("Can't pack ConstructLoadContext")
        }
	return append(cmd, save_area...), nil
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

/*
bool ComputeQuotedValue(TPM_ALG_ID alg, int credInfo_size, byte* credInfo,
                        int* size_quoted, byte* quoted)

ComputeMakeCredentialData()
 */
