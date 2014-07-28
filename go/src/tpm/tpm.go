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
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"os"
	"strconv"
)

// Supported TPM commands.
const (
	tagRQUCommand      uint16 = 0x00C1
	tagRQUAuth1Command uint16 = 0x00C2
	tagRQUAuth2Command uint16 = 0x00C3
	tagRSPCommand      uint16 = 0x00C4
	tagRSPAuth1Command uint16 = 0x00C5
	tagRSPAuth2Command uint16 = 0x00C6
)

// Supported TPM operations.
const (
	ordOIAP      uint32 = 0x0000000A
	ordOSAP      uint32 = 0x0000000B
	ordPCRExtend uint32 = 0x00000014
	ordPCRRead   uint32 = 0x00000015
	ordSeal      uint32 = 0x00000017
	ordUnseal    uint32 = 0x00000018
	ordGetRandom uint32 = 0x00000046
)

// Entity types
const (
	etKeyHandle uint16 = 0x0001
	etSRK       uint16 = 0x0004
	etKey       uint16 = 0x0005
)

// Entity values
const (
	khSRK uint32 = 0x40000000
)

// Each PCR has a fixed size of 20 bytes.
const PCRSize int = 20

// A CommandHeader is the header for a TPM command.
type CommandHeader struct {
	Tag  uint16
	Size uint32
	Cmd  uint32
}

// PackedSize computes the size of a sequence of types that can be passed to
// binary.Read or binary.Write.
func PackedSize(elts []interface{}) int {
	// Add the total size to the header.
	var size int
	for i := range elts {
		s := binary.Size(elts[i])
		if s == -1 {
			return -1
		}

		size += s
	}

	return size
}

// Pack takes a sequence of elements that are either of fixed length or slices
// of fixed-length types and packs them into a single byte array using
// binary.Write.
func Pack(elts []interface{}) ([]byte, error) {
	size := PackedSize(elts)
	if size <= 0 {
		return nil, errors.New("can't compute the size of the elements")
	}

	buf := bytes.NewBuffer(make([]byte, 0, size))

	for _, e := range elts {
		if err := binary.Write(buf, binary.BigEndian, e); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// PackWithHeader takes a header and a sequence of elements that are either of
// fixed length or slices of fixed-length types and packs them into a single
// byte array using binary.Write. It updates the CommandHeader to have the right
// length.
func PackWithHeader(ch CommandHeader, cmd []interface{}) ([]byte, error) {
	hdrSize := binary.Size(ch)
	bodySize := PackedSize(cmd)
	if bodySize < 0 {
		return nil, errors.New("couldn't compute packed size for message body")
	}

	ch.Size = uint32(hdrSize + bodySize)

	in := []interface{}{ch}
	in = append(in, cmd...)
	return Pack(in)
}

// A ResponseHeader is a header for TPM responses.
type ResponseHeader struct {
	Tag  uint16
	Size uint32
	Res  uint32
}

// A SliceSize is used to detect incoming variable-sized array responses. Note
// that any time there is a SliceSize followed by a slice in a respones, this
// slice must be resized to match its preceeding SliceSize after
// submitTPMRequest, since the Unpack code doesn't resize the underlying slice.
type SliceSize uint32

// A ResizeableSlice is a pointer to a slice so this slice can be resized
// dynamically. This is critical for cases like Seal, where we don't know
// beforehand exactly how many bytes the TPM might produce.
type ResizeableSlice *[]byte

// SimpleUnpack calls Unpack with a nil header and rest as 0. This is used when
// there is no resizeable slice.
func SimpleUnpack(b []byte, resp []interface{}) error {
    return Unpack(b, resp, nil, 0)
}

// Unpack decodes from a byte array a sequence of elements that are either
// pointers to fixed length types or slices of fixed-length types. It uses
// binary.Read to do the decoding. If rh is not nil, then the size is used to
// resize a ResizeableSlice.
func Unpack(b []byte, resp []interface{}, rh *ResponseHeader, rest uint) error {
	buf := bytes.NewBuffer(b)
	var resized bool
	for _, r := range resp {
        bs, ok := r.(ResizeableSlice)
        if ok {
            if rh == nil {
                return errors.New("found a ResizeableSlice but no header")
            }

            if resized {
                return errors.New("can't resize two arrays in a single response")
            }

            size := uint(rh.Size) - rest
            l := uint(len(*bs))
            if size > l {
                *bs = append(*bs, make([]byte, size - l)...)
            } else if size < l {
                *bs = (*bs)[:size]
            }

            resized = true
        }

		// Note that this only makes sense if the elements of resp are either
		// pointers or slices, since otherwise the decoded values just get
		// thrown away.
		if err := binary.Read(buf, binary.BigEndian, r); err != nil {
			return err
		}
	}

	if buf.Len() > 0 {
		return errors.New("unread bytes in the TPM response")
	}

	return nil
}

// submitTPMRequest sends a structure to the TPM device file and gets results
// back, interpreting them as a new provided structure.
func submitTPMRequest(f *os.File, tag uint16, ord uint32, in []interface{}, out []interface{}) error {
	ch := CommandHeader{tag, 0, ord}
	inb, err := PackWithHeader(ch, in)
	if err != nil {
		return err
	}

	if _, err := f.Write(inb); err != nil {
		return err
	}

	// Try to read the whole thing, but handle the case where it's just a
	// ResponseHeader and not the body, since that's what happens in the error
	// case.
	var rh ResponseHeader
	outSize := PackedSize(out)
	if outSize < 0 {
		return errors.New("invalid out arguments")
	}

	rhSize := binary.Size(rh)
	outb := make([]byte, rhSize+outSize)
	if _, err := f.Read(outb); err != nil {
		return err
	}

	if err := SimpleUnpack(outb[:rhSize], []interface{}{&rh}); err != nil {
		return err
	}

	// Check success before trying to read the rest of the result.
	// Note that the command tag and its associated response tag differ by 3,
	// e.g., tagRQUCommand == 0x00C1, and tagRSPCommand == 0x00C4.
	if rh.Tag != ch.Tag+3 {
		return errors.New("inconsistent tag returned by TPM")
	}

	if rh.Res != 0 {
		return tpmError(rh.Res)
	}

	if rh.Size > uint32(rhSize) {
        // Calculate the size of the rest of the structures (the ones that
        // aren't ResizeableSlice). This cast is safe, since we already know
        // that the encoding/binary package can compute the size of the response
        // header, so its return value will be nonnegative.
        rest := uint(binary.Size(&rh))
        for _, r := range out {
            if _, ok := r.(ResizeableSlice); !ok {
                rest += uint(binary.Size(r))
            }
        }

		if err := Unpack(outb[rhSize:], out, &rh, rest); err != nil {
			return err
		}
	}

	return nil
}
// ReadPCR reads a PCR value from the TPM.
func ReadPCR(f *os.File, pcr uint32) ([]byte, error) {
	in := []interface{}{pcr}
	v := make([]byte, PCRSize)
	out := []interface{}{v}
	if err := submitTPMRequest(f, tagRQUCommand, ordPCRRead, in, out); err != nil {
		return nil, err
	}

	return v, nil
}

// A PCRMask represents a set of PCR choices, one bit per PCR out of the 24
// possible PCR values.
type PCRMask [3]byte

// SetPCR sets a PCR value as selected in a given mask.
func (pm *PCRMask) SetPCR(i int) error {
	if i >= 24 || i < 0 {
		return errors.New("can't set PCR " + strconv.Itoa(i))
	}

	(*pm)[i/8] |= 1 << uint(i%8)
	return nil
}

// IsPCRSet checks to see if a given PCR is included in this mask.
func (pm PCRMask) IsPCRSet(i int) (bool, error) {
	if i >= 24 || i < 0 {
		return false, errors.New("can't check PCR " + strconv.Itoa(i))
	}

	n := byte(1 << uint(i%8))
	return pm[i/8]&n == n, nil
}

// FetchPCRValues gets a sequence of PCR values based on a mask.
func FetchPCRValues(f *os.File, mask PCRMask) ([]byte, error) {
	var pcrs []byte
	// There are a fixed 24 possible PCR indices.
	for i := 0; i < 24; i++ {
		set, err := mask.IsPCRSet(i)
		if err != nil {
			return nil, err
		}

		if set {
			pcr, err := ReadPCR(f, uint32(i))
			if err != nil {
				return nil, err
			}

			pcrs = append(pcrs, pcr...)
		}
	}

	return pcrs, nil
}

// A PCRSelection is the first element in the input a PCR composition, which is
// A PCRSelection, followed by the combined length of the PCR values,
// followed by the PCR values, all hashed under SHA-1.
type PCRSelection struct {
	Size uint16
	Mask PCRMask
}

// CreatePCRComposite composes a set of PCRs by prepending a PCRSelection and a
// length, then computing the SHA1 hash and returning its output.
func CreatePCRComposite(mask PCRMask, pcrs []byte) ([]byte, error) {
	if len(pcrs)%PCRSize != 0 {
		return nil, errors.New("pcrs must be a multiple of " + strconv.Itoa(PCRSize))
	}

	in := []interface{}{PCRSelection{3, mask}, uint32(len(pcrs)), pcrs}
	b, err := Pack(in)
	if err != nil {
		return nil, err
	}

	h := sha1.Sum(b)
	return h[:], nil
}

// A Nonce is a 20-byte value.
type Nonce [20]byte

const NonceSize uint32 = 20

// A TPMHandle is a 32-bit unsigned integer.
type TPMHandle uint32

// An OIAPResponse is a response to an OIAP command.
type OIAPResponse struct {
	AuthHandle TPMHandle
	NonceEven  Nonce
}

// OIAP sends an OIAP command to the TPM and gets back an auth value and a
// nonce.
func OIAP(f *os.File) (*OIAPResponse, error) {
	var resp OIAPResponse
	out := []interface{}{&resp}
	if err := submitTPMRequest(f, tagRQUCommand, ordOIAP, nil, out); err != nil {
		return nil, err
	}

	return &resp, nil
}

// GetRandom gets random bytes from the TPM.
func GetRandom(f *os.File, size uint32) ([]byte, error) {
	in := []interface{}{size}

	var outSize SliceSize
	b := make([]byte, int(size))
	out := []interface{}{&outSize, ResizeableSlice(&b)}

	if err := submitTPMRequest(f, tagRQUCommand, ordGetRandom, in, out); err != nil {
		return nil, err
	}

	return b, nil
}

// An OSAPCommand is a command sent for OSAP authentication.
type OSAPCommand struct {
	EntityType  uint16
	EntityValue uint32
	OddOSAP     Nonce
}

// An OSAPResponse is a TPM reply to an OSAPCommand.
type OSAPResponse struct {
	AuthHandle TPMHandle
	NonceEven  Nonce
	EvenOSAP   Nonce
}

// OSAP sends an OSAPCommand to the TPM and gets back authentication
// information in an OSAPResponse.
func OSAP(f *os.File, osap OSAPCommand) (*OSAPResponse, error) {
	in := []interface{}{osap}
	var resp OSAPResponse
	out := []interface{}{&resp}
	if err := submitTPMRequest(f, tagRQUCommand, ordOSAP, in, out); err != nil {
		return nil, err
	}

	return &resp, nil
}

// A Digest is a 20-byte SHA1 value.
type Digest [20]byte

const DigestSize uint32 = 20

// An AuthValue is a 20-byte value used for authentication.
type AuthValue [20]byte

// PCRInfoLong stores detailed information about PCRs.
type PCRInfoLong struct {
	Tag              uint16
	LocAtCreation    byte
	LocAtRelease     byte
	PCRsAtCreation   PCRSelection
	PCRsAtRelease    PCRSelection
	DigestAtCreation Digest
	DigestAtRelease  Digest
}

// A SealCommand is the command sent to the TPM to seal data.
type SealCommand struct {
	KeyHandle TPMHandle
	EncAuth   AuthValue
}

// SealCommandAuth stores the auth information sent with a SealCommand.
type SealCommandAuth struct {
	AuthHandle  TPMHandle
	NonceOdd    Nonce
	ContSession byte
	PubAuth     AuthValue
}

// SealResponse contains the auth information returned from a SealCommand.
type SealResponse struct {
	NonceEven   Nonce
	ContSession byte
	PubAuth     AuthValue
}

// Seal performs a seal operation on the TPM.
func Seal(f *os.File, sc *SealCommand, pcrs *PCRInfoLong, data []byte, sca *SealCommandAuth) ([]byte, *SealResponse, error) {
	datasize := uint32(len(data))
	pcrsize := binary.Size(pcrs)
	if pcrsize < 0 {
		return nil, nil, errors.New("Couldn't compute the size of a PCRInfoLong")
	}

	in := []interface{}{sc, uint32(pcrsize), pcrs, datasize, data, sca}

	// The slice will be resized by Unpack to the size of the sealed value.
	b := make([]byte, datasize)
	var resp SealResponse
	out := []interface{}{&b, &resp}
	if err := submitTPMRequest(f, tagRQUAuth1Command, ordSeal, in, out); err != nil {
		return nil, nil, err
	}

	return b, &resp, nil
}
