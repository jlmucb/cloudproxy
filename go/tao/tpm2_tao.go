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
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/tpm2"
)

func EncodeTwoBytes(b1 []byte, b2 []byte) ([]byte) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, uint16(len(b1)))
	if err != nil {
		return nil
	}
	err = binary.Write(buf, binary.BigEndian, b1)
	if err != nil {
		return nil
	}
	err = binary.Write(buf, binary.BigEndian, uint16(len(b2)))
	if err != nil {
		return nil
	}
	err = binary.Write(buf, binary.BigEndian, b2)
	if err != nil {
		return nil
	}
	return buf.Bytes()
}

func DecodeTwoBytes(b []byte) ([]byte, []byte) {
	buf := bytes.NewBuffer(b)
	var size uint16
	err := binary.Read(buf, binary.BigEndian, &size)
	if err != nil {
		return nil, nil
	}
	b1 := make([]byte, size, size)
	binary.Read(buf, binary.BigEndian, b1)
	err = binary.Read(buf, binary.BigEndian, &size)
	if err != nil {
		return nil, nil
	}
	b2 := make([]byte, size, size)
	binary.Read(buf, binary.BigEndian, b2)
	return b1, b2
}

// A TPM2Tao implements the Tao using a hardware TPM device.
type TPM2Tao struct {
	// rw is the device through which TPM2Tao communicates with the TPM.
	// usually /dev/tpm0.
	rw io.ReadWriteCloser

	// State path (includes config info)
	path string

	// ekCert
	ekCert []byte

	// password is the password.
	password string

	// ekHandle is an integer handle for an ek held by the TPM.
	ekContext []byte
	ekHandle tpm2.Handle

	// rootHandle is an integer handle for an root key held by the TPM.
	rootContext []byte
	rootHandle tpm2.Handle

	// signHandle is an integer handle for an signing held by the TPM.
	signContext []byte
	signHandle tpm2.Handle

	// session handle
	policy_digest []byte
	sessionContext []byte
	sessionHandle tpm2.Handle

	// verifier is a representation of the ek that can be used to verify Attestations.
	verifier *rsa.PublicKey

	// pcrCount is the number of PCRs in the TPM. 
	// implementation fixes this at 24.
	pcrCount uint32
	pcrNums  []int
	pcrVals  [][]byte
	pcrs	 []int

	// The name of the TPM2Tao is tpm(...K...) with extensions that represent the
	// PCR values (and maybe someday the locality).
	name auth.Prin

	// The current TPM2Tao code uses only locality 0, so this value is never set.
	locality byte
}

func (tt *TPM2Tao) loadEk() (tpm2.Handle, error) {
	keySize := uint16(2048)
	ek, _, err := tpm2.CreateEndorsement(tt.rw, keySize, tt.pcrs)
	if err != nil {
		return nil, err
	}
	return ek, nil
}

func (tt *TPM2Tao) loadRoot() (tpm2.Handle, error) {
	rh, err := tpm2.LoadContext(tt.rw, tt.rootContext)
	if err != nil {
		return nil, errors.New("Load Context fails for root")
	}
	return rh, nil
}

func (tt *TPM2Tao) loadQuote() (tpm2.Handle, error) {
	sh, err := tpm2.LoadContext(tt.rw, tt.signContext)
	if err != nil {
		return nil, errors.New("Load Context fails for quote")
	}
	return sh, nil
}

func (tt *TPM2Tao) loadSession() (tpm2.Handle, []byte, error) {
	sh, digest, err = tpm2.AssistCreateSession(tt.rw,
		tpm2.AlgTPM_ALG_SHA1, tt.pcrs)
	if err != nil {
		return nil, nil, err
	}
	return sh, digest, nil
}

func (tt *TPM2Tao) Rand() io.Reader {
	return tt.rw
}

func ReadPcrs(rw io.ReadWriter, pcrNums []int) ([][]byte, error) {
	pcrVals := make([][]byte, len(pcrNums))
	for i, v := range pcrNums {
		pcr, _ := tpm2.SetShortPcrs([]int{v})
		_, _, _, pv, err := tpm2.ReadPcrs(rw, byte(4), pcr)
		if err != nil {
			return nil, err
		}
		pcrVals[i] = pv
	}
	return pcrVals, nil
}

func MakeTPM2Prin(verifier *rsa.PublicKey, pcrNums []int, pcrVals [][]byte) (auth.Prin, error) {
	ek, err := x509.MarshalPKIXPublicKey(verifier)
	if err != nil {
		return auth.Prin{}, err
	}

	name := auth.Prin{
		Type: "tpm2",
		Key:  auth.Bytes(ek),
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

// FinalizeTPM2Tao releases the resources for the TPM2Tao.
func FinalizeTPM2Tao(tt *TPM2Tao) {
	if  tt.sessionHandle != 0 {
		tpm2.FlushContext(tt.rw, tpm2.Handle(tt.sessionHandle))
	}
	tt.sessionHandle = 0
	if  tt.ekHandle != 0 {
		tpm2.FlushContext(tt.rw, tpm2.Handle(tt.ekHandle))
	}
	tt.ekHandle = 0
	if  tt.signHandle != 0 {
		tpm2.FlushContext(tt.rw, tpm2.Handle(tt.signHandle))
	}
	tt.signHandle = 0

	// Release the file handle.
	tt.rw.Close()
}

// Remove this
func (tt *TPM2Tao) TmpRm() {

	if tt.ekHandle != 0 {
                tpm2.FlushContext(tt.rw, tt.ekHandle)
        }
        tt.ekHandle = 0

        if tt.signHandle != 0 {
                tpm2.FlushContext(tt.rw, tt.signHandle)
        }
        tt.signHandle = 0
}

// GetTaoName returns the Tao principal name assigned to the caller.
func (tt *TPM2Tao) GetTaoName() (name auth.Prin, err error) {
	return tt.name, nil
}

// ExtendTaoName irreversibly extends the Tao principal name of the caller.
func (tt *TPM2Tao) ExtendTaoName(subprin auth.SubPrin) error {
	return errors.New("name extensions are not supported for TPM2Tao")
}

// GetRandomBytes returns a slice of n random bytes.
func (tt *TPM2Tao) GetRandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("invalid number of requested random bytes")
	}
	return tpm2.GetRandom(tt.rw, uint32(n))
}

// ReadRandom implements io.Reader to read random bytes from the TPM2Tao.
func (tt *TPM2Tao) ReadRandom(p []byte) (int, error) {
	bytes, err := tt.GetRandomBytes(len(p))
	if err != nil {
		return 0, err
	}

	copy(p, bytes)
	return len(p), nil
}

// GetSharedSecret returns a slice of n secret bytes.
func (tt *TPM2Tao) GetSharedSecret(n int, policy string) (bytes []byte, err error) {
	return nil, errors.New("the TPM2Tao does not implement GetSharedSecret")
}

// NewTPM2Tao creates a new TPM2Tao and returns it under the Tao interface.
func NewTPM2Tao(tpmPath string, statePath string, pcrNums []int) (Tao, error) {
	var err error
	tt := &TPM2Tao{pcrCount: 24,
		       password: "",}

	tt.rw, err = tpm2.OpenTPM(tpmPath)
	if err != nil {
		return nil, err
	}

	// Make sure the TPM2Tao releases all its resources
	runtime.SetFinalizer(tt, FinalizeTPM2Tao)

	tt.pcrs = pcrNums

	keySize := uint16(2048)
	ek, _, err = tpm2.CreateEndorsement(tt.rw, keySize, tt.pcrs)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(tt.rw, ek)

	tt.verifier, err = tpm2.GetRsaKeyFromHandle(tt.rw, tpm2.Handle(tt.ekHandle))
	if err != nil {
		return nil, err
	}

	// Get the pcr values for the PCR nums.
	tt.pcrNums = make([]int, len(pcrNums))
	for i, v := range pcrNums {
		tt.pcrNums[i] = v
	}

	tt.pcrVals, err = ReadPcrs(tt.rw, pcrNums)
	if err != nil {
		return nil, err
	}

	// Create principal.
	tt.name, err = MakeTPM2Prin(tt.verifier, tt.pcrNums, tt.pcrVals)
	if err != nil {
		return nil, err
	}

	// Load handles for unsealing and attestation
	tt.path = statePath
	rn := []string{tt.path, "rootContext.bin"}
	sn := []string{tt.path, "quoteContext.bin"}
	rootFileName := strings.Join(rn, "/")
	signFileName := strings.Join(sn, "/")

	tt.rootContext, err = ioutil.ReadFile(rootFileName)
	if err != nil {
		return nil, errors.New("Can't read root context file")
	}

	tt.signContext, err := ioutil.ReadFile(signFileName)
	if err != nil {
		return nil, errors.New("Can't read sign context file")
	}

	return tt, nil
}

// Attest requests the Tao host sign a statement on behalf of the caller. The
// optional issuer, time and expiration will be given default values if nil.
func (tt *TPM2Tao) Attest(issuer *auth.Prin, start, expiration *int64,
		message auth.Form) (*Attestation, error) {
	qK, err := tt.loadQuote()
	if err != nil {
		return nil, errors.New("Can't load quote key")
	}
	defer tpm2.FlushContext(tt.rw, qk)
	if issuer == nil {
		issuer = &tt.name
	} else if !auth.SubprinOrIdentical(*issuer, tt.name) {
		return nil, errors.New("invalid issuer in statement")
	}

	// TODO(tmroeder): we assume here that the PCRs haven't changed (e.g., been
	// extended) since this TPM2Tao was created. If they have, then the PCRs will
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
	sig, _, err := tpm2.Quote(tt.rw, qk, "", tt.password,
			ser, tt.pcrs, uint16(tpm2.AlgTPM_ALG_NULL))
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
func (tt *TPM2Tao) Seal(data []byte, policy string) ([]byte, error) {
	rH, err := tt.loadRoot()
	if err != nil {
		return nil, errors.New("Can't load root key")
	}
	defer tpm2.FlushContext(tt.rw, rH)
	sK, policy_digest, err := tt.loadSession()
	if err != nil {
		return nil, errors.New("Can't load root key")
	}
	defer tpm2.FlushContext(tt.rw, sK)
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

	priv, pub, err := tpm2.AssistSeal(tt.rw, rH, ckb,
				"", tt.password, tt.pcrs, policy_digest)
	if err != nil {
		return nil, err
	}

	// encode pub and priv
	s := EncodeTwoBytes(pub, priv)

	h := &HybridSealedData{
		SealedKey:     s,
		EncryptedData: c,
	}

	return proto.Marshal(h)
}

// Unseal decrypts data that has been sealed by the Seal() operation, but only
// if the policy specified during the Seal() operation is satisfied.
func (tt *TPM2Tao) Unseal(sealed []byte) (data []byte, policy string, err error) {
	rH, err := tt.loadRoot()
	if err != nil {
		return nil, errors.New("Can't load root key")
	}
	defer tpm2.FlushContext(tt.rw, rH)
	sH, policy_digest, err := tt.loadSession()
	if err != nil {
		return nil, errors.New("Can't load root key")
	}
	defer tpm2.FlushContext(tt.rw, sH)

	// The sealed data is a HybridSealedData.
	var h HybridSealedData
	if err := proto.Unmarshal(sealed, &h); err != nil {
		return nil, "", err
	}

	// Decode buffer containing pub and priv blobs
	pub, priv := DecodeTwoBytes(h.SealedKey)
	unsealed, _, err := tpm2.AssistUnseal(tt.rw, sH,
		rH, pub, priv, "", tt.password, policy_digest)
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
func extractTpm2PCRs(p auth.Prin) ([]int, []byte, error) {
	return nil, nil, nil
	if p.Type != "tpm2" {
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

// extractAttest gets an RSA public key from the TPM principal name.
func extractAttest(p auth.Prin) (*rsa.PublicKey, error) {
	// The principal's Key should be a binary SubjectPublicKeyInfo.
	if p.Type != "tpm2" {
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

	ek, ok := pk.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("wrong type of public key: only RSA is supported for EKs")
	}

	return ek, nil
}
