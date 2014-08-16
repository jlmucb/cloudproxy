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

package tao

import (
	"errors"
	"io"
	"io/ioutil"
	"os"

	"cloudproxy/tao/auth"

	"github.com/google/go-tpm/tpm"
)

// A TPMTao implements the Tao using a hardware TPM device.
type TPMTao struct {
    // tpmfile is the file through which TPMTao communicates with the TPM. E.g.,
    // on Linux, this is usually /dev/tpm0.
	tpmfile   *os.File

    // srkAuth is the authenticator for the SRK. In most simple cases, it's 20
    // bytes of zeros. That value is called the "well-known authentictor"
	srkAuth   [20]byte

    // aikHandle is an integer handle for an AIK held by the TPM. This key is
    // used for creating Quote values from the TPM.
	aikHandle tpm.Handle

    // pcrCount is the number of PCRs in the TPM. The current go-tpm
    // implementation fixes this at 24.
	pcrCount  uint32

    pcrs []int
    pcrVals [][]byte
}

// NewTPMTao creates a new TPMTao and returns it under the Tao interface.
func NewTPMTao(tpmPath, aikblobPath string, pcrNums []int) (Tao, error) {
	var err error
	tt := &TPMTao{pcrCount: 24}
	tt.tpmfile, err = os.OpenFile(tpmPath, os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}

	// For now, the SRK Auth value is all zero, which is the well-known value.
	// So, we don't set it here.
	// TODO(tmroeder): add support for general SRK auth values.

	// TODO(tmroeder): the current tpm implementation in go-tpm assumes 24 PCRs.
	// This is not true in general, and it should be generalized there then
	// changed here.
	blob, err := ioutil.ReadFile(aikblobPath)
	if err != nil {
		return nil, err
	}

	tt.aikHandle, err = tpm.LoadKey2(tt.tpmfile, blob, tt.srkAuth[:])
	if err != nil {
		return nil, err
	}

    // Get the pcr values for the PCR nums.
    tt.pcrs = make([]int, len(pcrNums))
    tt.pcrVals = make([][]byte, len(pcrNums))
    for i, v := range pcrNums {
        tt.pcrs[i] = v
        pv, err := tpm.ReadPCR(tt.tpmfile, uint32(v))
        if err != nil {
            return nil, err
        }
        tt.pcrVals = append(tt.pcrVals, pv)
    }

	return tt, nil
}

// GetTaoName returns the Tao principal name assigned to the caller.
func (tt *TPMTao) GetTaoName() (name auth.Prin, err error) {

	return auth.Prin{}, errors.New("not implemented: GetTaoName")
}

// ExtendTaoName irreversibly extends the Tao principal name of the caller.
func (tt *TPMTao) ExtendTaoName(subprin auth.SubPrin) error {
	return errors.New("not implemented: ExtendTaoName")
}

// GetRandomBytes returns a slice of n random bytes.
func (tt *TPMTao) GetRandomBytes(n int) (bytes []byte, err error) {
	return nil, errors.New("not implemented: GetRandomBytes")
}

// Rand produces an io.Reader for random bytes from this Tao.
func (tt *TPMTao) Rand() io.Reader {
	return nil
}

// GetSharedSecret returns a slice of n secret bytes.
func (tt *TPMTao) GetSharedSecret(n int, policy string) (bytes []byte, err error) {
	return nil, errors.New("not implemented: GetSharedSecret")
}

// Attest requests the Tao host sign a statement on behalf of the caller. The
// optional issuer, time and expiration will be given default values if nil.
// TODO(kwalsh) Maybe create a struct for these optional params? Or use
// auth.Says instead (in which time and expiration are optional) with a
// bogus Speaker field like key("") or nil("") or self, etc.
func (tt *TPMTao) Attest(issuer *auth.Prin, time, expiration *int64, message auth.Form) (*Attestation, error) {
	return nil, errors.New("not implemented: Attest")
}

// Seal encrypts data so only certain hosted programs can unseal it.
func (tt *TPMTao) Seal(data []byte, policy string) (sealed []byte, err error) {
	return nil, errors.New("not implemented: Seal")
}

// Unseal decrypts data that has been sealed by the Seal() operation, but only
// if the policy specified during the Seal() operation is satisfied.
func (tt *TPMTao) Unseal(sealed []byte) (data []byte, policy string, err error) {
	return nil, "", errors.New("not implemented: Unseal")
}
