// Package tpm supports direct communication with a tpm device under Linux.
package tpm

import (
	"bytes"
	"encoding/binary"
	"os"
)

// TPM constants for messages.
const (
	TagRQUCommand      uint16 = 0x00C1
	TagRQUAuth1Command uint16 = 0x00C2
	TagRQUAuth2Command uint16 = 0x00C3

	OrdPCRExtend       uint32 = 0x00000014
	OrdPCRRead         uint32 = 0x00000015
	OrdPCRReset        uint32 = 0x000000C8
	OrdNVReadValue     uint32 = 0x000000CF
	OrdNVWriteValue    uint32 = 0x000000CD
	OrdGetCapability   uint32 = 0x00000065
	OrdSeal            uint32 = 0x00000017
	OrdUnseal          uint32 = 0x00000018
	OrdOSAP            uint32 = 0x0000000B
	OrdOIAP            uint32 = 0x0000000A
	OrdSaveState       uint32 = 0x00000098
	OrdQuote2          uint32 = 0x0000003E
	OrdGetRandom       uint32 = 0x00000046
	OrdLoadKey2        uint32 = 0x00000041
	OrdTerminateHandle uint32 = 0x00000096
	OrdGetPubKey       uint32 = 0x00000021

    ETKeyHandle        uint16 = 0x0001
    ETSRK              uint16 = 0x0004
    ETKey              uint16 = 0x0005
    KHSRK              uint32 = 0x40000000

    KeyTypeSRK         int = 1
    KeyTypeAIK         int = 2

    MaxPCRs            int = 24
    MaxBuf             int = 4096 // Do I need this?

    PCRSize            int = 20
)

// TODO(tmroeder): what is this? Looks like big-endian uint16 then 4 uint32.
// The format here looks like the standard command format: uint16 command type,
// then a size, then data. And why does it say 22 in the original when it
// clearly only has 18 bytes? I've replaced it with 18 here.
var tpmCapBlob = [18]byte{
	0, 193,
	0, 0, 0, 18,
	0, 0, 0, 101,
	0, 0, 0, 6,
	0, 0, 0, 0,
}

// A PCRSelection selects PCRs for a TPM operation
type PCRSelection struct {
	Size uint16
	Mask [3]byte
}

// A PCRLongInfo keeps information about PCRs.
type PCRLongInfo struct {
	Tag            uint16
	CreationLoc    byte
	ReleaseLoc     byte
	CreationPCRs   PCRSelection
	ReleasePCRs    PCRSelection
	CreationDigest [20]byte
	ReleaseDigest  [20]byte
}

// A PCRShortInfo keeps information about PCRs.
type PCRShortInfo struct {
	ReleasePCRs   PCRSelection
	ReleaseLoc    byte
	ReleaseDigest [20]byte
}

// A PublicKeyParams stores parameters for a public key.
type PublicKeyParams struct {
	AlgID     uint32
	EncScheme uint16
	SigScheme uint16
	ParamSize uint32
	Params    [32]byte
}

// A PublicKeyStore stores information about a public key.
type PublicKeyStore struct {
	KeyLen uint32
	Key    [256]byte
}

// A PublicKey is a public key stored by the TPM.
type PublicKey struct {
	Params PublicKeyParams
	Key    PublicKeyStore
}

// submitTPMRequest sends a structure to the TPM device file and gets results
// back, interpreting them as a new provided structure.
func submitTPMRequest(f *os.File, in interface{}, out interface{}) error {
    inBytes := make([]byte, binary.Size(in))
    if _, err := EncodeTPMStruct(inBytes, in); err != nil {
        return err
    }

	if _, err := f.Write(inBytes); err != nil {
		return err
	}

    outBytes := make([]byte, binary.Size(out))
	if _, err := f.Read(outBytes); err != nil {
		return err
	}

    if _, err := DecodeTPMStruct(out, outBytes); err != nil {
        return err
    }

	return nil
}

// EncodeTPMStruct encodes a TPM data structure into dest, writing integers in
// big-endian format, and returns the number
// of bytes written.
func EncodeTPMStruct(dest []byte, src interface{}) (int, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, src); err != nil {
		return 0, err
	}

	b := buf.Bytes()
	copy(dest, b)
	return len(b), nil
}

// DecodeTPMStruct decodes a slice into a TPM data structure, reading integers
// in big-endian format, and returns the number of bytes read.
func DecodeTPMStruct(dest interface{}, src []byte) (int, error) {
	buf := bytes.NewBuffer(src)
	if err := binary.Read(buf, binary.BigEndian, dest); err != nil {
		return 0, err
	}

	return len(src), nil
}

// A CommandHeader is the header for a TPM command
type CommandHeader struct {
    Tag uint16
    Size uint32
}

// A PCRReadCommand is a command structure for reading a PCR value.
type PCRReadCommand struct {
    Hdr CommandHeader
    Cmd uint32
    PCR uint32
}

// ReadPCR reads a PCR value from the TPM.
func ReadPCR(f *os.File, pcr int) ([]byte, error) {
    read := &PCRReadCommand{
        Hdr: CommandHeader{TagRQUCommand, 0},
        Cmd: OrdPCRRead,
        PCR: uint32(pcr),
    }

    read.Hdr.Size = uint32(binary.Size(read))

    // The TPM is supposed to return the 20-byte PCR value
    v := make([]byte, PCRSize)
    if err := submitTPMRequest(f, read, v); err != nil {
        return nil, err
    }

    return v, nil
}
