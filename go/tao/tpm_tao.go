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
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-tpm/tpm"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

// A TPMTao implements the Tao using a hardware TPM device.
type TPMTao struct {
	// tpmfile is the file through which TPMTao communicates with the TPM. E.g.,
	// on Linux, this is usually /dev/tpm0.
	tpmfile *os.File

	// srkAuth is the authenticator for the SRK. In most simple cases, it's 20
	// bytes of zeros. That value is called the "well-known authentictor"
	srkAuth [20]byte

	// aikHandle is an integer handle for an AIK held by the TPM. This key is
	// used for creating Quote values from the TPM.
	aikHandle tpm.Handle

	// verifier is a representation of the AIK that can be used to verify Quote
	// and Quote2 attestations.
	verifier *rsa.PublicKey

	// pcrCount is the number of PCRs in the TPM. The current go-tpm
	// implementation fixes this at 24.
	pcrCount uint32
	pcrNums  []int
	pcrVals  [][]byte

	// The name of the TPMTao is tpm(...K...) with extensions that represent the
	// PCR values (and maybe someday the locality).
	name auth.Prin

	// The current TPMTao code uses only locality 0, so this value is never set.
	locality byte
}

// NewTPMTao creates a new TPMTao and returns it under the Tao interface.
func NewTPMTao(tpmPath string, aikblob []byte, pcrNums []int) (Tao, error) {
	var err error
	tt := &TPMTao{pcrCount: 24}
	tt.tpmfile, err = os.OpenFile(tpmPath, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	// Make sure the TPMTao releases all its resources
	runtime.SetFinalizer(tt, FinalizeTPMTao)

	// For now, the SRK Auth value is all zero, which is the well-known value.
	// So, we don't set it here.
	// TODO(tmroeder): add support for general SRK auth values.

	// TODO(tmroeder): the current tpm implementation in go-tpm assumes 24 PCRs.
	// This is not true in general, and it should be generalized there then
	// changed here.
	tt.aikHandle, err = tpm.LoadKey2(tt.tpmfile, aikblob, tt.srkAuth[:])
	if err != nil {
		return nil, err
	}

	tt.verifier, err = tpm.UnmarshalRSAPublicKey(aikblob)
	if err != nil {
		return nil, err
	}

	// Get the pcr values for the PCR nums.
	tt.pcrNums = make([]int, len(pcrNums))
	for i, v := range pcrNums {
		tt.pcrNums[i] = v
	}

	tt.pcrVals, err = ReadPCRs(tt.tpmfile, pcrNums)
	if err != nil {
		return nil, err
	}

	// Create principal.
	tt.name, err = MakeTPMPrin(tt.verifier, tt.pcrNums, tt.pcrVals)
	if err != nil {
		return nil, err
	}

	return tt, nil
}

// FinalizeTPMTao releases the resources for the TPMTao.
func FinalizeTPMTao(tt *TPMTao) {
	// Flush the AIK.
	tt.aikHandle.CloseKey(tt.tpmfile)

	// Release the file handle.
	tt.tpmfile.Close()
}

// GetTaoName returns the Tao principal name assigned to the caller.
func (tt *TPMTao) GetTaoName() (name auth.Prin, err error) {
	return tt.name, nil
}

// ExtendTaoName irreversibly extends the Tao principal name of the caller.
func (tt *TPMTao) ExtendTaoName(subprin auth.SubPrin) error {
	tt.name = tt.name.MakeSubprincipal(subprin)
	return nil
}

// GetRandomBytes returns a slice of n random bytes.
func (tt *TPMTao) GetRandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("invalid number of requested random bytes")
	}
	return tpm.GetRandom(tt.tpmfile, uint32(n))
}

// Read implements io.Reader to read random bytes from the TPMTao.
func (tt *TPMTao) Read(p []byte) (int, error) {
	bytes, err := tt.GetRandomBytes(len(p))
	if err != nil {
		return 0, err
	}

	copy(p, bytes)
	return len(p), nil
}

// Rand produces an io.Reader for random bytes from this Tao.
func (tt *TPMTao) Rand() io.Reader {
	return tt
}

// GetSharedSecret returns a slice of n secret bytes.
func (tt *TPMTao) GetSharedSecret(n int, policy string) (bytes []byte, err error) {
	return nil, errors.New("the TPMTao does not implement GetSharedSecret")
}

// Attest requests the Tao host sign a statement on behalf of the caller. The
// optional issuer, time and expiration will be given default values if nil.
func (tt *TPMTao) Attest(issuer *auth.Prin, start, expiration *int64, message auth.Form) (*Attestation, error) {
	if issuer == nil {
		issuer = &tt.name
	} else if !auth.SubprinOrIdentical(*issuer, tt.name) {
		return nil, errors.New("invalid issuer in statement")
	}

	// TODO(tmroeder): we assume here that the PCRs haven't changed (e.g., been
	// extended) since this TPMTao was created. If they have, then the PCRs will
	// be wrong when we extend the principal here with them as the first
	// component. This doesn't matter at the moment, since we don't currently
	// support extending the PCRs or clearing them, but it will need to be
	// changed when we do.
	stmt := auth.Says{
		Speaker:    *issuer,
		Time:       start,
		Expiration: expiration,
		Message:    message,
	}

	// This is done in GenerateAttestation, but the TPM attestation is signed
	// differently, so we do the time calculations here.
	t := time.Now()
	if stmt.Time == nil {
		i := t.UnixNano()
		stmt.Time = &i
	}

	if stmt.Expiration == nil {
		i := t.Add(365 * 24 * time.Hour).UnixNano()
		stmt.Expiration = &i
	}

	ser := auth.Marshal(stmt)
	// TODO(tmroeder): check the pcrVals for sanity once we support extending or
	// clearing the PCRs.
	sig, _, err := tpm.Quote(tt.tpmfile, tt.aikHandle, ser, tt.pcrNums, tt.srkAuth[:])
	if err != nil {
		return nil, err
	}

	// Pull off the extensions from the name to get the bare TPM key for the
	// signer.
	signer := auth.Prin{
		Type: tt.name.Type,
		Key:  tt.name.Key,
	}
	a := &Attestation{
		SerializedStatement: ser,
		Signature:           sig,
		Signer:              auth.Marshal(signer),
	}
	return a, nil
}

// Seal encrypts data so only certain hosted programs can unseal it. Note that
// at least some TPMs can only seal up to 149 bytes of data. So, we employ a
// hybrid encryption scheme that seals a key and uses the key to encrypt the
// data separately. We use the keys infrastructure to perform secure and
// flexible encryption.
func (tt *TPMTao) Seal(data []byte, policy string) (sealed []byte, err error) {
	if policy != SealPolicyDefault {
		return nil, errors.New("tpm-specific policies are not yet implemented")
	}

	crypter, err := GenerateCrypter()
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(crypter.aesKey)
	defer ZeroBytes(crypter.hmacKey)

	c, err := crypter.Encrypt(data)
	if err != nil {
		return nil, err
	}

	ck, err := MarshalCrypterProto(crypter)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(ck.Key)

	ckb, err := proto.Marshal(ck)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(ckb)

	s, err := tpm.Seal(tt.tpmfile, tt.locality, tt.pcrNums, ckb, tt.srkAuth[:])
	if err != nil {
		return nil, err
	}

	h := &HybridSealedData{
		SealedKey:     s,
		EncryptedData: c,
	}

	return proto.Marshal(h)
}

// Unseal decrypts data that has been sealed by the Seal() operation, but only
// if the policy specified during the Seal() operation is satisfied.
func (tt *TPMTao) Unseal(sealed []byte) (data []byte, policy string, err error) {
	// The sealed data is a HybridSealedData.
	var h HybridSealedData
	if err := proto.Unmarshal(sealed, &h); err != nil {
		return nil, "", err
	}

	unsealed, err := tpm.Unseal(tt.tpmfile, h.SealedKey, tt.srkAuth[:])
	if err != nil {
		return nil, "", err
	}
	defer ZeroBytes(unsealed)

	var ck CryptoKey
	if err := proto.Unmarshal(unsealed, &ck); err != nil {
		return nil, "", err
	}
	defer ZeroBytes(ck.Key)

	crypter, err := UnmarshalCrypterProto(&ck)
	if err != nil {
		return nil, "", err
	}
	defer ZeroBytes(crypter.aesKey)
	defer ZeroBytes(crypter.hmacKey)

	m, err := crypter.Decrypt(h.EncryptedData)
	if err != nil {
		return nil, "", err
	}

	return m, SealPolicyDefault, nil
}

// extractPCRs gets the PCRs from a tpm principal.
func extractPCRs(p auth.Prin) ([]int, []byte, error) {
	if p.Type != "tpm" {
		return nil, nil, errors.New("can only extract PCRs from a TPM principal")
	}

	// The PCRs are stored as the first subprincipal value, with name "PCRs".
	if len(p.Ext) == 0 {
		return nil, nil, errors.New("no subprincipals available for PCR extraction")
	}

	if p.Ext[0].Name != "PCRs" {
		return nil, nil, errors.New("the first subprincipal must have Name 'PCRs' for PCR extraction to work")
	}

	sp := p.Ext[0]
	if len(sp.Arg) != 2 {
		return nil, nil, errors.New("the PCRs subprincipal must have exactly two arguments")
	}

	// auth.Str is exactly a string.
	arg0, ok0 := sp.Arg[0].(auth.Str)
	arg1, ok1 := sp.Arg[1].(auth.Str)
	if !ok0 || !ok1 {
		return nil, nil, errors.New("both Terms in the PCRs subprincipal must be strings")
	}

	nums := strings.Split(string(arg0), ",")
	vals := strings.Split(string(arg1), ",")
	if len(nums) != len(vals) {
		return nil, nil, errors.New("mismatched count between PCR nums and vals")
	}

	pcrNums := make([]int, len(nums))
	var pcrVals []byte
	for i, v := range nums {
		n, err := strconv.ParseInt(v, 10, 16)
		if err != nil {
			return nil, nil, err
		}
		pcrNums[i] = int(n)

		b, err := hex.DecodeString(vals[i])
		if err != nil {
			return nil, nil, err
		}
		pcrVals = append(pcrVals, b...)
	}
	return pcrNums, pcrVals, nil
}

// extractAIK gets an RSA public key from the TPM principal name.
func extractAIK(p auth.Prin) (*rsa.PublicKey, error) {
	// The principal's Key should be a binary SubjectPublicKeyInfo.
	if p.Type != "tpm" {
		return nil, errors.New("wrong type of principal: should be 'tpm'")
	}

	k, ok := p.Key.(auth.Bytes)
	if !ok {
		return nil, errors.New("the AIK key must be an auth.Bytes values")
	}
	pk, err := x509.ParsePKIXPublicKey([]byte(k))
	if err != nil {
		return nil, err
	}

	aik, ok := pk.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("wrong type of public key: only RSA is supported for AIKs")
	}

	return aik, nil
}

func ReadPCRs(tpmfile *os.File, pcrNums []int) ([][]byte, error) {
	pcrVals := make([][]byte, len(pcrNums))
	for i, v := range pcrNums {
		pv, err := tpm.ReadPCR(tpmfile, uint32(v))
		if err != nil {
			return nil, err
		}
		pcrVals[i] = pv
	}
	return pcrVals, nil
}

func MakeTPMPrin(verifier *rsa.PublicKey, pcrNums []int, pcrVals [][]byte) (auth.Prin, error) {
	aik, err := x509.MarshalPKIXPublicKey(verifier)
	if err != nil {
		return auth.Prin{}, err
	}

	name := auth.Prin{
		Type: "tpm",
		Key:  auth.Bytes(aik),
	}

	asp := auth.PrinExt{
		Name: "PCRs",
		Arg:  make([]auth.Term, 2),
	}
	var pcrNumStrs []string
	for _, v := range pcrNums {
		pcrNumStrs = append(pcrNumStrs, strconv.Itoa(v))
	}
	asp.Arg[0] = auth.Str(strings.Join(pcrNumStrs, ","))

	var pcrValStrs []string
	for _, p := range pcrVals {
		pcrValStrs = append(pcrValStrs, hex.EncodeToString(p))
	}
	asp.Arg[1] = auth.Str(strings.Join(pcrValStrs, ","))

	// The PCRs are the first extension of the name.
	name.Ext = []auth.PrinExt{asp}

	return name, nil
}
