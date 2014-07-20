// Package tpm supports direct communication with a tpm device under Linux.
package tpm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"strconv"
)

// TPM constants for messages.
const (
	TagRQUCommand uint16 = 0x00C1
	OrdPCRExtend  uint32 = 0x00000014
	OrdPCRRead    uint32 = 0x00000015
	OrdOSAP       uint32 = 0x0000000B
	OrdOIAP       uint32 = 0x0000000A
	OrdGetRandom  uint32 = 0x00000046
	PCRSize       int    = 20
)

// A Result is a return value from the TPM.
type Result uint32

const (
	Success Result = iota
	BuffTooSmallError
	UnauthorizedError
	FunctionFailedError
)

// resultErrors maps Results to their associated error strings.
var resultErrors = map[Result]string{
	Success:             "success",
	BuffTooSmallError:   "buffer too small",
	UnauthorizedError:   "unauthorized",
	FunctionFailedError: "function failed",
}

// Error produces a string for the given TPM Error code
func (r Result) Error() string {
	if s, ok := resultErrors[r]; ok {
		return s
	}

	return "Unknown error code " + strconv.Itoa(int(r))
}

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
// binary.Write. The first element of the sequence must be a *CommandHeader.
func Pack(cmd []interface{}) ([]byte, error) {
	hdr, ok := cmd[0].(*CommandHeader)
	if !ok {
		return nil, errors.New("first packed element must be a CommandHeader")
	}

	size := PackedSize(cmd)
	if size <= 0 {
		return nil, errors.New("can't compute the size of the command")
	}

	hdr.Size = uint32(size)
	buf := bytes.NewBuffer(make([]byte, 0, size))
	for i := range cmd {
		if err := binary.Write(buf, binary.BigEndian, cmd[i]); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// A header for TPM responses.
type ResponseHeader struct {
	Tag  uint16
	Size uint32
	Res  Result
}

// Unpack decodes from a byte array a sequence of elements that either either
// pointers to fixed length types or slices of fixed-length types. It uses
// binary.Read to do the decoding. If the first element of the resp sequence is
// a *ResponseHeader, then the Result field will be checked for success.
func Unpack(b []byte, resp []interface{}) error {
	hdr, ok := resp[0].(*ResponseHeader)
	buf := bytes.NewBuffer(b)
	var start int
	if ok {
		if err := binary.Read(buf, binary.BigEndian, hdr); err != nil {
			return err
		}

		if hdr.Res != Success {
			return hdr.Res
		}
		start = 1
	}

	for i := start; i < len(resp); i++ {
		if err := binary.Read(buf, binary.BigEndian, resp[i]); err != nil {
			return err
		}
	}

	return nil
}

// submitTPMRequest sends a structure to the TPM device file and gets results
// back, interpreting them as a new provided structure.
func submitTPMRequest(f *os.File, in []interface{}, out []interface{}) error {
	inb, err := Pack(in)
	if err != nil {
		return err
	}

	if _, err := f.Write(inb); err != nil {
		return err
	}

	outSize := PackedSize(out)
	if outSize <= 0 {
		return errors.New("can't compute the size of the response")
	}

	// TODO(tmroeder): this assumes (probably incorrectly) that the TPM will
	// write the same number of bytes whether the command succeeds or not. It's
	// more likely that the TPM will return only a response header if the
	// command fails. In that case, I need to read the response header first,
	// then decide what action to take. And I should probably separate out the
	// header from the rest of the output interface.
	outb := make([]byte, outSize)
	if _, err := f.Read(outb); err != nil {
		return err
	}

	if err := Unpack(outb, out); err != nil {
		return err
	}

	return nil
}

// ReadPCR reads a PCR value from the TPM.
func ReadPCR(f *os.File, pcr uint32) ([]byte, error) {
	in := []interface{}{
		&CommandHeader{TagRQUCommand, 0, OrdPCRRead},
		pcr,
	}

	// The TPM is supposed to return the 20-byte PCR value
	v := make([]byte, PCRSize)
	if err := submitTPMRequest(f, in, []interface{}{v}); err != nil {
		return nil, err
	}

	return v, nil
}

// The response to an OIAPCommand.
type OIAPResponse struct {
	Auth      uint32
	NonceEven [20]byte
}

// OIAP sends an OIAP command to the TPM and gets back an auth value and a
// nonce.
func OIAP(f *os.File) (*OIAPResponse, error) {
	in := []interface{}{&CommandHeader{TagRQUCommand, 0, OrdOIAP}}

	var rh ResponseHeader
	var resp OIAPResponse
	out := []interface{}{&rh, &resp}

	if err := submitTPMRequest(f, in, out); err != nil {
		return nil, err
	}

	return &resp, nil
}

// GetRandom gets random bytes from the TPM.
func GetRandom(f *os.File, size uint32) ([]byte, error) {
	in := []interface{}{
		&CommandHeader{TagRQUCommand, 0, OrdGetRandom},
		size,
	}

	var rh ResponseHeader
	var outSize uint32
	b := make([]byte, int(size))
	out := []interface{}{&rh, &outSize, b}

	if err := submitTPMRequest(f, in, out); err != nil {
		return nil, err
	}

	if outSize != size {
		return nil, errors.New("wrong size from GetRandom")
	}

	return b, nil
}

// An OSAPCommand is a command sent for OSAP authentication.
type OSAPCommand struct {
	EntryType  uint16
	EntryValue uint32
	OddOSAP    [20]byte
}

// An OSAPResponse is a TPM reply to an OSAPCommand.
type OSAPResponse struct {
	Auth      uint32
	NonceEven [20]byte
	EvenOSAP  [20]byte
}

// OSAP sends an OSAPCommand to the TPM and gets back authentication
// information in an OSAPResponse.
func OSAP(f *os.File, entryType uint16, entryValue uint32, oddOSAP [20]byte) (*OSAPResponse, error) {
	in := []interface{}{
		&CommandHeader{TagRQUCommand, 0, OrdOSAP},
		OSAPCommand{entryType, entryValue, oddOSAP},
	}

	var rh ResponseHeader
	var resp OSAPResponse
	out := []interface{}{&rh, &resp}

	if err := submitTPMRequest(f, in, out); err != nil {
		return nil, err
	}

	return &resp, nil
}
