// Package tpm supports direct communication with a tpm device under Linux.
package tpm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
)

// Supported TPM commands.
const (
	tagRQUCommand uint16 = 0x00C1
	tagRSPCommand uint16 = 0x00C4
)

// Supported TPM operations.
const (
	ordOSAP      uint32 = 0x0000000B
	ordOIAP      uint32 = 0x0000000A
	ordPCRExtend uint32 = 0x00000014
	ordPCRRead   uint32 = 0x00000015
	ordGetRandom uint32 = 0x00000046
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
func Pack(ch CommandHeader, cmd []interface{}) ([]byte, error) {
	hdrSize := binary.Size(ch)
	bodySize := PackedSize(cmd)
	if bodySize <= 0 {
		return nil, errors.New("can't compute the size of the command")
	}

	size := hdrSize + bodySize
	ch.Size = uint32(size)
	buf := bytes.NewBuffer(make([]byte, 0, size))

	// The header goes first, unsurprisingly.
	if err := binary.Write(buf, binary.BigEndian, ch); err != nil {
		return nil, err
	}

	for _, c := range cmd {
		if err := binary.Write(buf, binary.BigEndian, c); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// A ResponseHeader is a header for TPM responses.
type ResponseHeader struct {
	Tag  uint16
	Size uint32
	Res  uint32
}

// A SliceSize is used to detect incoming variable-sized array responses.
type SliceSize uint32

// Unpack decodes from a byte array a sequence of elements that are either
// pointers to fixed length types or slices of fixed-length types. It uses
// binary.Read to do the decoding.
func Unpack(b []byte, resp []interface{}) error {
	buf := bytes.NewBuffer(b)
	var nextSliceSize SliceSize
	for _, r := range resp {
		if nextSliceSize > 0 {
			// This must be a byte slice to resize.
			bs, ok := r.([]byte)
			if !ok {
				return errors.New("a *SliceSize must be followed by a []byte")
			}

			if int(nextSliceSize) > len(b) {
				return errors.New("the TPM returned more bytes than can fit in the supplied slice")
			}

			// Resize the slice to match the number of bytes the TPM says it
			// returned for this value.
			r = bs[:nextSliceSize]
			nextSliceSize = 0
		}

		// Note that this only makes sense if the elements of resp are either
		// pointers or slices, since otherwise the decoded values just get
		// thrown away.
		if err := binary.Read(buf, binary.BigEndian, r); err != nil {
			return err
		}

		if ss, ok := r.(*SliceSize); ok {
			nextSliceSize = *ss
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
	inb, err := Pack(ch, in)
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

	if err := Unpack(outb[:rhSize], []interface{}{&rh}); err != nil {
		return err
	}

	// Check success before trying to read the rest of the result.
	if rh.Tag != tagRSPCommand {
		return errors.New("inconsistent tag returned by TPM")
	}

	if rh.Res != 0 {
		return tpmError(rh.Res)
	}

	if rh.Size > uint32(rhSize) {
		if err := Unpack(outb[rhSize:], out); err != nil {
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

// An OIAPResponse is a response to an OIAPCommand.
type OIAPResponse struct {
	Auth      uint32
	NonceEven [20]byte
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
	out := []interface{}{&outSize, b}

	if err := submitTPMRequest(f, tagRQUCommand, ordGetRandom, in, out); err != nil {
		return nil, err
	}

	return b[:outSize], nil
}

// An OSAPCommand is a command sent for OSAP authentication.
type OSAPCommand struct {
	EntityType  uint16
	EntityValue uint32
	OddOSAP     [20]byte
}

// An OSAPResponse is a TPM reply to an OSAPCommand.
type OSAPResponse struct {
	Auth      uint32
	NonceEven [20]byte
	EvenOSAP  [20]byte
}

// OSAP sends an OSAPCommand to the TPM and gets back authentication
// information in an OSAPResponse.
func OSAP(f *os.File, entityType uint16, entityValue uint32, oddOSAP [20]byte) (*OSAPResponse, error) {
	in := []interface{}{OSAPCommand{entityType, entityValue, oddOSAP}}
	var resp OSAPResponse
	out := []interface{}{&resp}
	if err := submitTPMRequest(f, tagRQUCommand, ordOSAP, in, out); err != nil {
		return nil, err
	}

	return &resp, nil
}
