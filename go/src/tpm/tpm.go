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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/golang/glog"
)

// Supported TPM commands.
const (
	tagPCRInfoLong     uint16 = 0x06
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
	ordPCRRead   uint32 = 0x00000015
	ordSeal      uint32 = 0x00000017
	ordUnseal    uint32 = 0x00000018
	ordGetRandom uint32 = 0x00000046
)

// Entity types
const (
	etSRK uint16 = 0x0004
)

// A tpmHandle is a 32-bit unsigned integer.
type tpmHandle uint32

// Entity values
const (
	khSRK tpmHandle = 0x40000000
)

// Each PCR has a fixed size of 20 bytes.
const PCRSize int = 20

// A commandHeader is the header for a TPM command.
type commandHeader struct {
	Tag  uint16
	Size uint32
	Cmd  uint32
}

// String prints a string version of a commandHeader
func (ch commandHeader) String() string {
	return fmt.Sprintf("commandHeader{Tag: %x, Size: %x, Cmd: %x}", ch.Tag, ch.Size, ch.Cmd)
}

// packedSize computes the size of a sequence of types that can be passed to
// binary.Read or binary.Write.
func packedSize(elts []interface{}) int {
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

// pack takes a sequence of elements that are either of fixed length or slices
// of fixed-length types and packs them into a single byte array using
// binary.Write.
func pack(elts []interface{}) ([]byte, error) {
	size := packedSize(elts)
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

// packWithHeader takes a header and a sequence of elements that are either of
// fixed length or slices of fixed-length types and packs them into a single
// byte array using binary.Write. It updates the CommandHeader to have the right
// length.
func packWithHeader(ch commandHeader, cmd []interface{}) ([]byte, error) {
	hdrSize := binary.Size(ch)
	bodySize := packedSize(cmd)
	if bodySize < 0 {
		return nil, errors.New("couldn't compute packed size for message body")
	}

	ch.Size = uint32(hdrSize + bodySize)

	in := []interface{}{ch}
	in = append(in, cmd...)
	return pack(in)
}

// A responseHeader is a header for TPM responses.
type responseHeader struct {
	Tag  uint16
	Size uint32
	Res  uint32
}

// String writes out a string representation of a responseHeader.
func (rh responseHeader) String() string {
	return fmt.Sprintf("responseHeader{Tag: %x, Size: %x, Res: %x", rh.Tag, rh.Size, rh.Res)
}

// A resizeableSlice is a pointer to a slice so this slice can be resized
// dynamically. This is critical for cases like Seal, where we don't know
// beforehand exactly how many bytes the TPM might produce.
type resizeableSlice *[]byte

// SimpleUnpack calls Unpack with a nil header and rest as 0. This is used when
// there is no resizeable slice.
func simpleUnpack(b []byte, resp []interface{}) error {
	return unpack(b, resp, nil, 0)
}

// unpack decodes from a byte array a sequence of elements that are either
// pointers to fixed length types or slices of fixed-length types. It uses
// binary.Read to do the decoding. If rh is not nil, then the size is used to
// resize a ResizeableSlice. The size of the byte array is taken to be rh.Size -
// rest.
func unpack(b []byte, resp []interface{}, rh *responseHeader, rest uint) error {
	buf := bytes.NewBuffer(b)
	var resized bool
	for _, r := range resp {
		bs, ok := r.(resizeableSlice)
		if ok {
			if rh == nil {
				return errors.New("found a resizeableSlice but no header")
			}

			if resized {
				return errors.New("can't resize two arrays in a single response")
			}

			size := uint(rh.Size) - rest
			l := uint(len(*bs))
			if size > l {
				*bs = append(*bs, make([]byte, size-l)...)
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

// maxTPMResponse is the largest possible response from the TPM. We need to know
// this because we don't always know the length of the TPM response, and
// /dev/tpm insists on giving it all back in a single value rather than
// returning a header and a body in separate responses.
const maxTPMResponse = 4096

// submitTPMRequest sends a structure to the TPM device file and gets results
// back, interpreting them as a new provided structure.
func submitTPMRequest(f *os.File, tag uint16, ord uint32, in []interface{}, out []interface{}) error {
	ch := commandHeader{tag, 0, ord}
	inb, err := packWithHeader(ch, in)
	if err != nil {
		return err
	}

	if glog.V(2) {
		glog.Infof("TPM request:\n%x\n", inb)
	}
	if _, err := f.Write(inb); err != nil {
		return err
	}

	// Try to read the whole thing, but handle the case where it's just a
	// ResponseHeader and not the body, since that's what happens in the error
	// case.
	var rh responseHeader
	outSize := packedSize(out)
	if outSize < 0 {
		return errors.New("invalid out arguments")
	}

	rhSize := binary.Size(rh)
	outb := make([]byte, maxTPMResponse)
	outlen, err := f.Read(outb)
	if err != nil {
		return err
	}

	// Resize the buffer to match the amount read from the TPM.
	outb = outb[:outlen]
	if glog.V(2) {
		glog.Infof("TPM response:\n%x\n", outb)
	}

	if err := simpleUnpack(outb[:rhSize], []interface{}{&rh}); err != nil {
		return err
	}

	// Check success before trying to read the rest of the result.
	// Note that the command tag and its associated response tag differ by 3,
	// e.g., tagRQUCommand == 0x00C1, and tagRSPCommand == 0x00C4.
	if rh.Res != 0 {
		return tpmError(rh.Res)
	}

	if rh.Tag != ch.Tag+3 {
		return errors.New("inconsistent tag returned by TPM. Expected " + strconv.Itoa(int(ch.Tag+3)) + " but got " + strconv.Itoa(int(rh.Tag)))
	}

	if rh.Size > uint32(rhSize) {
		// Calculate the size of the rest of the structures (the ones that
		// aren't ResizeableSlice). This cast is safe, since we already know
		// that the encoding/binary package can compute the size of the response
		// header, so its return value will be nonnegative.
		rest := uint(binary.Size(&rh))
		for _, r := range out {
			if _, ok := r.(resizeableSlice); !ok {
				rest += uint(binary.Size(r))
			}
		}

		if err := unpack(outb[rhSize:], out, &rh, rest); err != nil {
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

// A pcrSelection is the first element in the input a PCR composition, which is
// A pcrSelection, followed by the combined length of the PCR values,
// followed by the PCR values, all hashed under SHA-1.
type pcrSelection struct {
	Size uint16
	Mask PCRMask
}

// String writes out a string representation of a pcrSelection
func (p pcrSelection) String() string {
	return fmt.Sprintf("pcrSelection{Size: %x, Mask: % x}", p.Size, p.Mask)
}

// createPCRComposite composes a set of PCRs by prepending a pcrSelection and a
// length, then computing the SHA1 hash and returning its output.
func createPCRComposite(mask PCRMask, pcrs []byte) ([]byte, error) {
	if len(pcrs)%PCRSize != 0 {
		return nil, errors.New("pcrs must be a multiple of " + strconv.Itoa(PCRSize))
	}

	in := []interface{}{pcrSelection{3, mask}, uint32(len(pcrs)), pcrs}
	b, err := pack(in)
	if err != nil {
		return nil, err
	}
	if glog.V(2) {
		glog.Infof("composite buffer for mask %s is % x\n", mask, b)
	}

	h := sha1.Sum(b)
	if glog.V(2) {
		glog.Infof("SHA1 hash of composite buffer is % x\n", h)
	}

	return h[:], nil
}

// A nonce is a 20-byte value.
type nonce [20]byte

const nonceSize uint32 = 20

// An oiapResponse is a response to an OIAP command.
type oiapResponse struct {
	AuthHandle tpmHandle
	NonceEven  nonce
}

// String writes out a string representation of an oiapResponse.
func (opr oiapResponse) String() string {
	return fmt.Sprintf("oiapResponse{AuthHandle: %x, NonceEven: % x}", opr.AuthHandle, opr.NonceEven)
}

// oiap sends an OIAP command to the TPM and gets back an auth value and a
// nonce.
func oiap(f *os.File) (*oiapResponse, error) {
	var resp oiapResponse
	out := []interface{}{&resp}
	if err := submitTPMRequest(f, tagRQUCommand, ordOIAP, nil, out); err != nil {
		return nil, err
	}

	return &resp, nil
}

// GetRandom gets random bytes from the TPM.
func GetRandom(f *os.File, size uint32) ([]byte, error) {
	in := []interface{}{size}

	var outSize uint32
	var b []byte
	out := []interface{}{&outSize, resizeableSlice(&b)}

	if err := submitTPMRequest(f, tagRQUCommand, ordGetRandom, in, out); err != nil {
		return nil, err
	}

	return b, nil
}

// An osapCommand is a command sent for OSAP authentication.
type osapCommand struct {
	EntityType  uint16
	EntityValue tpmHandle
	OddOSAP     nonce
}

// String writes out a string representation of an osapCommand.
func (opc osapCommand) String() string {
	return fmt.Sprintf("osapCommand{EntityType: %x, EntityValue: %x, OddOSAP: % x}", opc.EntityType, opc.EntityValue, opc.OddOSAP)
}

// An osapResponse is a TPM reply to an osapCommand.
type osapResponse struct {
	AuthHandle tpmHandle
	NonceEven  nonce
	EvenOSAP   nonce
}

// String returns a string representation of an osapResponse.
func (opr osapResponse) String() string {
	return fmt.Sprintf("osapResponse{AuthHandle: %x, NonceEven: % x, EvenOSAP: % x}", opr.AuthHandle, opr.NonceEven, opr.EvenOSAP)
}

// osap sends an OSAPCommand to the TPM and gets back authentication
// information in an OSAPResponse.
func osap(f *os.File, osap osapCommand) (*osapResponse, error) {
	in := []interface{}{osap}
	var resp osapResponse
	out := []interface{}{&resp}
	if err := submitTPMRequest(f, tagRQUCommand, ordOSAP, in, out); err != nil {
		return nil, err
	}

	return &resp, nil
}

// A Digest is a 20-byte SHA1 value.
type digest [20]byte

const digestSize uint32 = 20

// An AuthValue is a 20-byte value used for authentication.
type authValue [20]byte

const authSize uint32 = 20

// pcrInfoLong stores detailed information about PCRs.
type pcrInfoLong struct {
	Tag              uint16
	LocAtCreation    byte
	LocAtRelease     byte
	PCRsAtCreation   pcrSelection
	PCRsAtRelease    pcrSelection
	DigestAtCreation digest
	DigestAtRelease  digest
}

// String returns a string representation of a pcrInfoLong.
func (pcri pcrInfoLong) String() string {
	return fmt.Sprintf("pcrInfoLong{Tag: %x, LocAtCreation: %x, LocAtRelease: %x, PCRsAtCreation: %s, PCRsAtRelease: %s, DigestAtCreation: % x, DigestAtRelease: % x}", pcri.Tag, pcri.LocAtCreation, pcri.LocAtRelease, pcri.PCRsAtCreation, pcri.PCRsAtRelease, pcri.DigestAtCreation, pcri.DigestAtRelease)
}

// createPCRInfo creates a pcrInfoLong structure from a mask and some PCR
// values that match this mask, along with a TPM locality.
func createPCRInfo(loc byte, mask PCRMask, pcrVals []byte) (*pcrInfoLong, error) {
	d, err := createPCRComposite(mask, pcrVals)
	if err != nil {
		return nil, err
	}

	locVal := byte(1 << loc)
	pcri := &pcrInfoLong{
		Tag:            tagPCRInfoLong,
		LocAtCreation:  locVal,
		LocAtRelease:   locVal,
		PCRsAtCreation: pcrSelection{3, mask},
		PCRsAtRelease:  pcrSelection{3, mask},
	}

	copy(pcri.DigestAtRelease[:], d)
	copy(pcri.DigestAtCreation[:], d)

	if glog.V(2) {
		glog.Info("Created pcrInfoLong with serialized form %s\n", pcri)
	}

	return pcri, nil
}

// A sealCommand is the command sent to the TPM to seal data.
type sealCommand struct {
	KeyHandle tpmHandle
	EncAuth   authValue
}

// String returns a string representation of a sealCommand.
func (sc sealCommand) String() string {
	return fmt.Sprintf("sealCommand{KeyHandle: %x, EncAuth: % x}", sc.KeyHandle, sc.EncAuth)
}

// sealCommandAuth stores the auth information sent with a SealCommand.
type sealCommandAuth struct {
	AuthHandle  tpmHandle
	NonceOdd    nonce
	ContSession byte
	PubAuth     authValue
}

// String returns a string representation of a sealCommandAuth.
func (sca sealCommandAuth) String() string {
	return fmt.Sprintf("sealCommandAuth{AuthHandle: %x, NonceOdd: % x, ContSession: %x, PubAuth: % x}", sca.AuthHandle, sca.NonceOdd, sca.ContSession, sca.PubAuth)
}

// sealResponse contains the auth information returned from a sealCommand.
type sealResponse struct {
	NonceEven   nonce
	ContSession byte
	PubAuth     authValue
}

// String returns a string representation of a sealResponse.
func (sr sealResponse) String() string {
	return fmt.Sprintf("sealResponse{NonceEven: % x, ContSession: %x, PubAuth: % x}", sr.NonceEven, sr.ContSession, sr.PubAuth)
}

// seal performs a seal operation on the TPM.
func seal(f *os.File, sc *sealCommand, pcrs *pcrInfoLong, data []byte, sca *sealCommandAuth) ([]byte, *sealResponse, error) {
	datasize := uint32(len(data))
	pcrsize := binary.Size(pcrs)
	if pcrsize < 0 {
		return nil, nil, errors.New("Couldn't compute the size of a pcrInfoLong")
	}

	in := []interface{}{sc, uint32(pcrsize), pcrs, datasize, data, sca}

	// The slice will be resized by Unpack to the size of the sealed value.
	var b []byte
	var resp sealResponse
	out := []interface{}{resizeableSlice(&b), &resp}
	if err := submitTPMRequest(f, tagRQUAuth1Command, ordSeal, in, out); err != nil {
		return nil, nil, err
	}

	return b, &resp, nil
}

// unsealResponse contains the auth information returned from an unsealCommand.
type unsealResponse struct {
	NonceEven   nonce
	ContSession byte
	ResultAuth  authValue
}

// String returns a string representation of an unsealResponse.
func (ur unsealResponse) String() string {
	return fmt.Sprintf("unsealResponse{NonceEven: % x, ContSession: %x, ResultAuth: % x}", ur.NonceEven, ur.ContSession, ur.ResultAuth)
}

// unseal data sealed by the TPM.
func unseal(f *os.File, keyHandle tpmHandle, sealed []byte, auth1 *sealCommandAuth, auth2 *sealCommandAuth) ([]byte, *unsealResponse, *unsealResponse, error) {
	in := []interface{}{keyHandle, sealed, auth1, auth2}
	var outb []byte
	var size uint32
	var outAuth1 unsealResponse
	var outAuth2 unsealResponse
	out := []interface{}{&size, resizeableSlice(&outb), &outAuth1, &outAuth2}
	if err := submitTPMRequest(f, tagRQUAuth2Command, ordUnseal, in, out); err != nil {
		return nil, nil, nil, err
	}

	return outb, &outAuth1, &outAuth2, nil
}

// Seal encrypts data under PCR 17 and returns the sealed data.
func Seal(f *os.File, data []byte) ([]byte, error) {
	var mask PCRMask
	if err := mask.SetPCR(17); err != nil {
		return nil, err
	}

	if glog.V(2) {
		glog.Infof("mask is % x\n", mask)
	}

	pcrVals, err := FetchPCRValues(f, mask)
	if err != nil {
		return nil, err
	}

	if glog.V(2) {
		glog.Infof("pcrVals is % x\n", pcrVals)
	}

	// Locality is apparently always set to 0 in vTCIDirect.
	var locality byte
	pcrInfo, err := createPCRInfo(locality, mask, pcrVals)
	if err != nil {
		return nil, err
	}

	if glog.V(2) {
		glog.Infof("pcrInfo is %s\n", pcrInfo)
	}

	// Try to run OSAP for the SRK, reading a random OddOSAP for our initial
	// command.
	osapc := osapCommand{
		EntityType:  etSRK,
		EntityValue: khSRK,
	}

	if _, err := rand.Read(osapc.OddOSAP[:]); err != nil {
		return nil, err
	}

	if glog.V(2) {
		glog.Infof("osapCommand is %s\n", osapc)
	}

	osapr, err := osap(f, osapc)
	if err != nil {
		return nil, err
	}

	if glog.V(2) {
		glog.Infof("osapResponse is %s\n", osapr)
	}

	// A shared secret is computed as
	//
	// sharedSecret = HMAC-SHA1(srkAuth, evenosap||oddosap)
	//
	// where srkAuth is the hash of the SRK authentication (which hash is all 0s
	// for the well-known SRK auth value, which is what we're using right now),
	// and even and odd OSAP are the values from the OSAP protocol.
	osapData, err := pack([]interface{}{osapr.EvenOSAP, osapc.OddOSAP})
	if err != nil {
		return nil, err
	}

	if glog.V(2) {
		glog.Infof("osapData is % x\n", osapData)
	}

	// TODO(tmroeder): test this with secrets other than the well-known secret.
	// Note that this will require setting up the TPM differently.
	wellKnownAuth := make([]byte, authSize)
	if glog.V(2) {
		glog.Infof("wellKnownAuth is % x\n", wellKnownAuth)
	}

	hm := hmac.New(sha1.New, wellKnownAuth)
	hm.Write(osapData)
	sharedSecret := hm.Sum(nil)

	if glog.V(2) {
		glog.Infof("hmac size is %d\n", hm.Size())
		glog.Infof("sharedSecret is % x\n", sharedSecret)
		glog.Infof("length of shared secret is %d\n", len(sharedSecret))
	}

	// EncAuth is computed as
	//
	// encAuth = XOR(srkAuth, SHA1(sharedSecret || <lastEvenNonce>))
	//
	// In this case, the last even nonce is NonceEven from OSAP.
	xorData, err := pack([]interface{}{sharedSecret, osapr.NonceEven})
	if err != nil {
		return nil, err
	}

	if glog.V(2) {
		glog.Infof("xorData is % x\n", xorData)
	}

	encAuthData := sha1.Sum(xorData)

	if glog.V(2) {
		glog.Infof("encAuthData is % x\n", encAuthData)
	}

	// Zero out the xorData, since it contains the sharedSecret.
	//    for i := range xorData {
	//        xorData[i] = 0
	//    }

	sc := &sealCommand{KeyHandle: khSRK}

	for i := range sc.EncAuth {
		sc.EncAuth[i] = wellKnownAuth[i] ^ encAuthData[i]
	}

	if glog.V(2) {
		glog.Infof("sealCommand is %s\n", sc)
	}

	// The digest input to pubauth is
	//
	// digest = SHA1(ordSeal || encAuth || binary.Size(pcrInfo) || pcrInfo ||
	//               len(data) || data)
	//
	// and the PubAuth value is then
	//
	// PubAuth = HMAC-SHA1(sharedSecret, digest || NonceEven || NonceOdd ||
	//                     ContSession)
	//
	// where ContSession is the value chosen for sealCommandAuth
	digestBytes, err := pack([]interface{}{ordSeal, sc.EncAuth, uint32(binary.Size(pcrInfo)), pcrInfo, uint32(len(data)), data})
	if err != nil {
		return nil, err
	}

	if glog.V(2) {
		glog.Infof("digestBytes is % x\n", digestBytes)
	}

	digest := sha1.Sum(digestBytes)

	if glog.V(2) {
		glog.Infof("digest is % x\n", digest)
	}

	// Except for the auth handle from OSAP, all the values of the
	// sealCommandAuth start at 0, including ContSession and NonceOdd. We then
	// fill NonceOdd with strong random bytes and compute PubAuth according to
	// the standard TPM algorithm.
	sca := &sealCommandAuth{
		AuthHandle: osapr.AuthHandle,
	}
	if _, err := rand.Read(sca.NonceOdd[:]); err != nil {
		return nil, err
	}

	if glog.V(2) {
		glog.Infof("sealCommandAuth is %s\n", sca)
	}

	pubAuthBytes, err := pack([]interface{}{digest, osapr.NonceEven, sca.NonceOdd, sca.ContSession})
	if err != nil {
		return nil, err
	}

	if glog.V(2) {
		glog.Infof("pubAuthBytes is % x\n", pubAuthBytes)
	}

	hm2 := hmac.New(sha1.New, sharedSecret)
	hm2.Write(pubAuthBytes)
	pubAuth := hm2.Sum(nil)
	copy(sca.PubAuth[:], pubAuth[:])

	if glog.V(2) {
		glog.Infof("sealCommandAuth now is %s\n", sca)
	}

	sealed, _, err := seal(f, sc, pcrInfo, data, sca)
	if err != nil {
		return nil, err
	}

	return sealed, nil
}

// Unseal decrypts data encrypted by the TPM for PCR 17.
func Unseal(f *os.File, sealed []byte) ([]byte, error) {
	// Try to run OSAP for the SRK, reading a random OddOSAP for our initial
	// command.
	osapc := osapCommand{
		EntityType:  etSRK,
		EntityValue: khSRK,
	}

	if _, err := rand.Read(osapc.OddOSAP[:]); err != nil {
		return nil, err
	}

	if glog.V(2) {
		glog.Infof("osapCommand is %s\n", osapc)
	}

	osapr, err := osap(f, osapc)
	if err != nil {
		return nil, err
	}

	if glog.V(2) {
		glog.Infof("osapResponse is %s\n", osapr)
	}

	// A shared secret is computed as
	//
	// sharedSecret = HMAC-SHA1(srkAuth, evenosap||oddosap)
	//
	// where srkAuth is the hash of the SRK authentication (which hash is all 0s
	// for the well-known SRK auth value, which is what we're using right now),
	// and even and odd OSAP are the values from the OSAP protocol.
	osapData, err := pack([]interface{}{osapr.EvenOSAP, osapc.OddOSAP})
	if err != nil {
		return nil, err
	}

	if glog.V(2) {
		glog.Infof("osapData is % x\n", osapData)
	}

	// TODO(tmroeder): test this with secrets other than the well-known secret.
	// Note that this will require setting up the TPM differently.
	wellKnownAuth := make([]byte, authSize)
	if glog.V(2) {
		glog.Infof("wellKnownAuth is % x\n", wellKnownAuth)
	}

	hm := hmac.New(sha1.New, wellKnownAuth)
	hm.Write(osapData)
	sharedSecret := hm.Sum(nil)

	if glog.V(2) {
		glog.Infof("hmac size is %d\n", hm.Size())
		glog.Infof("sharedSecret is % x\n", sharedSecret)
		glog.Infof("length of shared secret is %d\n", len(sharedSecret))
	}

	// The unseal command needs an OIAP session in addition to the OSAP session.
	oiapr, err := oiap(f)
	if err != nil {
		return nil, err
	}

	// The digest for the unseal command is computed as
	//
	// digest = SHA1(ordUnseal || sealed)
	digestInput, err := pack([]interface{}{ordUnseal, sealed})
	if err != nil {
		return nil, err
	}

	digest := sha1.Sum(digestInput)

	// The first PubAuth value for unseal is computed as
	//
	// PubAuth = HMAC-SHA1(sharedSecret, digest || NonceEven || NonceOdd ||
	//                     ContSession)
	sca := &sealCommandAuth{
		AuthHandle: osapr.AuthHandle,
	}

	if _, err := rand.Read(sca.NonceOdd[:]); err != nil {
		return nil, err
	}

	pubAuthInput, err := pack([]interface{}{digest, osapr.NonceEven, sca.NonceOdd, sca.ContSession})
	if err != nil {
		return nil, err
	}

	h := hmac.New(sha1.New, sharedSecret)
	h.Write(pubAuthInput)
	pa := h.Sum(nil)
	copy(sca.PubAuth[:], pa[:])

	// The second PubAuth value for unseal is computed as
	//
	// PubAuth2 = HMAC-SHA1(srkAuth, digest || NonceEven2 || NonceOdd2 ||
	//                      ContSession2)
	sca2 := &sealCommandAuth{
		AuthHandle: oiapr.AuthHandle,
	}

	if _, err := rand.Read(sca2.NonceOdd[:]); err != nil {
		return nil, err
	}

	pubAuthInput2, err := pack([]interface{}{digest, oiapr.NonceEven, sca2.NonceOdd, sca2.ContSession})
	if err != nil {
		return nil, err
	}

	h2 := hmac.New(sha1.New, wellKnownAuth)
	h2.Write(pubAuthInput2)
	pa2 := h2.Sum(nil)
	copy(sca2.PubAuth[:], pa2[:])

	unsealed, _, _, err := unseal(f, khSRK, sealed, sca, sca2)
	if err != nil {
		return nil, err
	}

	return unsealed, nil
}
