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
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/tpm2"
	"github.com/jlmucb/cloudproxy/go/util"
)

func EncodeTwoBytes(b1 []byte, b2 []byte) []byte {
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

	// quote-key cert
	rootCert []byte

	// password is the password.
	password string

	// rootContext is the context for the root handle.
	rootContext []byte

	// quoteContext is the context for the quote key.
	quoteContext []byte
	quotePublic  []byte
	quoteCert    []byte

	// sealContext is a the context for sealing, held by the TPM.
	sealContext []byte
	sealPublic  []byte

	// session context is used by seal.
	sessionContext []byte

	// verifier is a representation of the root that can be used to verify Attestations.
	verifier *rsa.PublicKey

	// pcrCount is the number of PCRs in the TPM.
	// implementation fixes this at 24.
	pcrCount uint32
	pcrNums  []int
	pcrVals  [][]byte
	pcrs     []int

	// The name of the TPM2Tao is tpm2(...K...) with extensions that represent the
	// PCR values (and maybe someday the locality).
	name auth.Prin

	// The current TPM2Tao code uses only locality 0, so this value is never set.
	locality byte

	// tpm2 parameters
	nvHandle   tpm2.Handle
	authString string
}

// Loads keys from Blobs.
func (tt *TPM2Tao) loadKeyFromBlobs(ownerHandle tpm2.Handle, ownerPw string,
	objectPw string, publicBlob []byte,
	privateBlob []byte) (tpm2.Handle, error) {
	return tpm2.LoadKeyFromBlobs(tt.rw, ownerHandle, ownerPw, objectPw, publicBlob, privateBlob)
}

func (tt *TPM2Tao) loadRootContext() (tpm2.Handle, error) {
	rh, err := tpm2.LoadContext(tt.rw, tt.rootContext)
	if err != nil {
		return tpm2.Handle(0), errors.New("Load Context fails for root")
	}
	return rh, nil
}

func (tt *TPM2Tao) loadQuoteContext() (tpm2.Handle, error) {
	qh, err := tpm2.LoadContext(tt.rw, tt.quoteContext)
	if err != nil {
		return tpm2.Handle(0), errors.New("Load Context fails for quote")
	}
	return qh, nil
}

// IAH: does it build?
func (tt *TPM2Tao) loadSealContext() (tpm2.Handle, error) {
	sh, err := tpm2.LoadContext(tt.rw, tt.sealContext)
	if err != nil {
		return tpm2.Handle(0), errors.New("Load Context fails for root")
	}
	return sh, nil
}

func (tt *TPM2Tao) loadSessionContext() (tpm2.Handle, []byte, error) {
	sh, digest, err := tpm2.AssistCreateSession(tt.rw,
		tpm2.AlgTPM_ALG_SHA1, tt.pcrs)
	if err != nil {
		return tpm2.Handle(0), nil, err
	}
	return sh, digest, nil
}

func (tt *TPM2Tao) GetPcrNums() []int {
	return tt.pcrs
}

// TODO(jlm): Fix this to provide quoteHandle quoteHandle
// in structure should no longer be used.
func (tt *TPM2Tao) GetRsaTPMKey(handle tpm2.Handle) (*rsa.PublicKey, error) {
	return tpm2.GetRsaKeyFromHandle(tt.rw, handle)
}

func (tt *TPM2Tao) Rand() io.Reader {
	return tt.rw
}

func ReadTPM2PCRs(rw io.ReadWriter, pcrNums []int) ([][]byte, error) {
	fmt.Fprintf(os.Stderr, "Getting the PCRs\n")
	pcrVals := make([][]byte, len(pcrNums))
	for i, v := range pcrNums {
		fmt.Fprintf(os.Stderr, "Working on iteration %d\n", i)
		pcr, _ := tpm2.SetShortPcrs([]int{v})
		fmt.Fprintf(os.Stderr, "set short pcr %v, returned %v\n", v, pcr)
		_, _, _, pv, err := tpm2.ReadPcrs(rw, byte(4), pcr)
		fmt.Fprintf(os.Stderr, "got PCR value % x\n", pv)
		if err != nil {
			return nil, err
		}
		pcrVals[i] = pv
	}
	return pcrVals, nil
}

func MakeTPM2Prin(verifier *rsa.PublicKey, pcrNums []int, pcrVals [][]byte) (auth.Prin, error) {
	root, err := x509.MarshalPKIXPublicKey(verifier)
	if err != nil {
		return auth.Prin{}, err
	}

	name := auth.NewTPM2Prin(root)

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
	// Release the file handle.
	tt.rw.Close()
}

// GetTaoName returns the Tao principal name assigned to the caller.
func (tt *TPM2Tao) GetTaoName() (name auth.Prin, err error) {
	return tt.name, nil
}

// ExtendTaoName irreversibly extends the Tao principal name of the caller.
func (tt *TPM2Tao) ExtendTaoName(subprin auth.SubPrin) error {
	tt.name = tt.name.MakeSubprincipal(subprin)
	return nil
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
		password: ""}

	tt.rw, err = tpm2.OpenTPM(tpmPath)
	if err != nil {
		return nil, err
	}
	tpm2.Flushall(tt.rw)

	// Make sure the TPM2Tao releases all its resources
	runtime.SetFinalizer(tt, FinalizeTPM2Tao)

	tt.pcrs = pcrNums
	tt.path = statePath

	keySize := uint16(2048)
	quotePassword := ""

	quoteKeyPrivateBlobFile := path.Join(tt.path, "quote_private_key_blob")
	_, quotePrivateErr := os.Stat(quoteKeyPrivateBlobFile)
	quoteKeyPublicBlobFile := path.Join(tt.path, "quote_public_key_blob")
	_, quotePublicErr := os.Stat(quoteKeyPublicBlobFile)

	sealKeyPrivateBlobFile := path.Join(tt.path, "seal_private_key_blob")
	_, sealPrivateErr := os.Stat(sealKeyPrivateBlobFile)
	sealKeyPublicBlobFile := path.Join(tt.path, "seal_public_key_blob")
	_, sealPublicErr := os.Stat(sealKeyPublicBlobFile)

	var quoteKeyPublicBlob []byte
	var quoteKeyPrivateBlob []byte
	var sealKeyPublicBlob []byte
	var sealKeyPrivateBlob []byte

	// Create the root key.
	rootHandle, err := tpm2.CreateTpm2HierarchyRoot(tt.rw, tt.pcrs, keySize, uint16(tpm2.AlgTPM_ALG_SHA1))
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(tt.rw, rootHandle)

	if quotePrivateErr != nil || sealPrivateErr != nil || quotePublicErr != nil || sealPublicErr != nil {
		quoteKeyPublicBlob, quoteKeyPrivateBlob, sealKeyPublicBlob, sealKeyPrivateBlob, err =
			tpm2.CreateTpm2HierarchySubKeys(tt.rw, tt.pcrs, keySize, uint16(tpm2.AlgTPM_ALG_SHA1),
				rootHandle, quotePassword)
		if err != nil {
			return nil, err
		}
		// Save the blobs
		err = ioutil.WriteFile(quoteKeyPrivateBlobFile, quoteKeyPrivateBlob, 0644)
		if err != nil {
			return nil, errors.New("Can't write quoteKeyPrivateBlobFile")
		}
		err = ioutil.WriteFile(quoteKeyPublicBlobFile, quoteKeyPublicBlob, 0644)
		if err != nil {
			return nil, errors.New("Can't write quoteKeyPublicBlobFile")
		}
		err = ioutil.WriteFile(sealKeyPrivateBlobFile, sealKeyPrivateBlob, 0644)
		if err != nil {
			return nil, errors.New("Can't write sealKeyPrivateBlobFile")
		}
		err = ioutil.WriteFile(sealKeyPublicBlobFile, sealKeyPublicBlob, 0644)
		if err != nil {
			return nil, errors.New("Can't write sealKeyPrivateBlobFile")
		}
	} else {
		quoteKeyPrivateBlob, err = ioutil.ReadFile(quoteKeyPrivateBlobFile)
		if err != nil {
			return nil, fmt.Errorf("Could not read the quote key from %s: %v", quoteKeyPrivateBlobFile, err)
		}
		quoteKeyPublicBlob, err = ioutil.ReadFile(quoteKeyPublicBlobFile)
		if err != nil {
			return nil, fmt.Errorf("Could not read the quote key from %s: %v", quoteKeyPublicBlobFile, err)
		}

		sealKeyPrivateBlob, err = ioutil.ReadFile(sealKeyPrivateBlobFile)
		if err != nil {
			return nil, fmt.Errorf("Could not read the seal key from %s: %v", sealKeyPrivateBlobFile, err)
		}
		sealKeyPublicBlob, err = ioutil.ReadFile(sealKeyPublicBlobFile)
		if err != nil {
			return nil, fmt.Errorf("Could not read the seal key from %s: %v", sealKeyPublicBlobFile, err)
		}
	}

	// Load the sub-keys.
	quoteHandle, err := tt.loadKeyFromBlobs(rootHandle, "", quotePassword, quoteKeyPublicBlob, quoteKeyPrivateBlob)
	if err != nil {
		return nil, fmt.Errorf("Could not load quote keys from blobs %s", err)
	}
	defer tpm2.FlushContext(tt.rw, quoteHandle)
	sealHandle, err := tt.loadKeyFromBlobs(rootHandle, "", quotePassword, sealKeyPublicBlob, sealKeyPrivateBlob)
	if err != nil {
		return nil, fmt.Errorf("Could not load seal key from blobs")
	}
	defer tpm2.FlushContext(tt.rw, sealHandle)

	// Save the contexts for later.
	tt.rootContext, err = tpm2.SaveContext(tt.rw, rootHandle)
	if err != nil {
		return nil, fmt.Errorf("Could not save the root context")
	}
	tt.quoteContext, err = tpm2.SaveContext(tt.rw, quoteHandle)
	if err != nil {
		return nil, fmt.Errorf("Could not save the quote context")
	}
	tt.sealContext, err = tpm2.SaveContext(tt.rw, sealHandle)
	if err != nil {
		return nil, fmt.Errorf("Could not save the seal context")
	}

	if tt.verifier, err = tpm2.GetRsaKeyFromHandle(tt.rw, quoteHandle); err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "Loaded the handles and the verifier\n")

	// Get the pcr values for the PCR nums.
	tt.pcrNums = make([]int, len(pcrNums))
	for i, v := range pcrNums {
		tt.pcrNums[i] = v
	}

	tt.pcrVals, err = ReadTPM2PCRs(tt.rw, pcrNums)
	if err != nil {
		return nil, err
	}

	// Create principal.
	tt.name, err = MakeTPM2Prin(tt.verifier, tt.pcrNums, tt.pcrVals)
	if err != nil {
		return nil, err
	}

	quoteCertPath := path.Join(tt.path, "quote_cert")
	if _, quoteCertErr := os.Stat(quoteCertPath); quoteCertErr != nil {
		tt.quoteCert, err = getQuoteCert(tt.rw, tt.path, quoteHandle, quotePassword, tt.name, tt.verifier)
		if err != nil {
			return nil, err
		}
		err = ioutil.WriteFile(quoteCertPath, tt.quoteCert, 0644)
		if err != nil {
			return nil, err
		}
	} else {
		tt.quoteCert, err = ioutil.ReadFile(quoteCertPath)
		if err != nil {
			return nil, err
		}
	}
	fmt.Fprintf(os.Stderr, "Got TPM 2.0 principal name %q\n", tt.name)
	return tt, nil
}

// getActivateResponse gets encrypted cert from attest service.
func getActivateResponse(filePath string, request tpm2.AttestCertRequest) (*tpm2.AttestCertResponse, error) {

	// If the file filePath/service_location exists, use that address/port, otherwise use default.
	network := "tcp"
	address := "localhost:8121"
	serviceFileName := path.Join(filePath, "service_location")
	serviceInfo, err := ioutil.ReadFile(serviceFileName)
	if err == nil {
		address = string(serviceInfo)
	}
	if len(address) > 256 {
		return nil, errors.New("Bad service address string")
	}

	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	ms := util.NewMessageStream(conn)
	_, err = ms.WriteMessage(&request)
	if err != nil {
		return nil, err
	}
	var response tpm2.AttestCertResponse
	err = ms.ReadMessage(&response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

// getQuoteCert requests and acquires a certificate for the quote key.
// TODO(tmroeder): for now, this returns a dummy value for the cert.
func getQuoteCert(rw io.ReadWriteCloser, filePath string, quoteHandle tpm2.Handle,
	quotePassword string, name auth.Prin, verifier *rsa.PublicKey) ([]byte, error) {

	// Generate Ek.
	ekHandle, _, err := tpm2.CreateEndorsement(rw, 2048, []int{17, 18})
	if err != nil {
		return nil, fmt.Errorf("Could not open endorsement handle")
	}
	defer tpm2.FlushContext(rw, ekHandle)

	// Get endorsement cert.
	endorsementFile := path.Join(filePath, "endorsement_cert")
	derEndorsementCert, err := ioutil.ReadFile(endorsementFile)
	if err != nil {
		return nil, fmt.Errorf("Could not read endorsement from %s: %v",
			endorsementFile, err)
	}

	request, err := tpm2.BuildAttestCertRequest(rw, quoteHandle, ekHandle,
		derEndorsementCert, name.String(), quotePassword)
	if err != nil {
		return nil, fmt.Errorf("Could not build cert request %v", err)
	}

	// Send request to attest service
	response, err := getActivateResponse(filePath, *request)
	if err != nil {
		return nil, fmt.Errorf("Could not activate quote key %v", err)
	}

	if response == nil || response.Error == nil || *response.Error != 0 {
		return nil, fmt.Errorf("AttestCertResponse is nil or has non-zero error")
	}
	// Recover cert.
	quoteCert, err := tpm2.GetCertFromAttestResponse(rw, quoteHandle, ekHandle,
		quotePassword, *response)
	if err != nil {
		return nil, fmt.Errorf("Could not get cert from AttestCertResponse %v", err)
	}
	return quoteCert, nil
}

// Attest requests the Tao host seal a statement on behalf of the caller. The
// optional issuer, time and expiration will be given default values if nil.
func (tt *TPM2Tao) Attest(issuer *auth.Prin, start, expiration *int64,
	message auth.Form) (*Attestation, error) {
	fmt.Fprintf(os.Stderr, "About to load the quote key in attest\n")
	qh, err := tt.loadQuoteContext()
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(tt.rw, qh)

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

	// This is done in GenerateAttestation, but the TPM attestation is sealed
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

	var pcrVals [][]byte
	toQuote, err := tpm2.FormatTpm2Quote(ser, tt.pcrs, pcrVals)
	if err != nil {
		return nil, errors.New("Can't format tpm2 Quote")
	}

	// TODO(tmroeder): check the pcrVals for sanity once we support extending or
	// clearing the PCRs.
	quote_struct, sig, err := tpm2.Quote(tt.rw, qh, "", tt.password,
		toQuote, tt.pcrs, uint16(tpm2.AlgTPM_ALG_NULL))
	if err != nil {
		return nil, err
	}

	quoteKey, err := x509.MarshalPKIXPublicKey(tt.verifier)
	if err != nil {
		return nil, err
	}

	// TODO(kwalsh) remove Tpm2QuoteStructure from Attestation structure
	a := &Attestation{
		SerializedStatement: ser,
		Signature:           sig,
		SignerType:          proto.String("tpm2"),
		SignerKey:           quoteKey,
		Tpm2QuoteStructure:  quote_struct,
		RootEndorsement:     tt.quoteCert,
	}

	return a, nil
}

// Seal encrypts data so only certain hosted programs can unseal it. Note that
// at least some TPMs can only seal up to 149 bytes of data. So, we employ a
// hybrid encryption scheme that seals a key and uses the key to encrypt the
// data separately. We use the keys infrastructure to perform secure and
// flexible encryption.
func (tt *TPM2Tao) Seal(data []byte, policy string) ([]byte, error) {
	rh, err := tt.loadRootContext()
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(tt.rw, rh)

	sk, policy_digest, err := tt.loadSessionContext()
	if err != nil {
		return nil, errors.New("Can't load root key")
	}
	defer tpm2.FlushContext(tt.rw, sk)

	if policy != SealPolicyDefault {
		return nil, errors.New("tpm-specific policies are not yet implemented")
	}

	crypter, err := GenerateCrypter()
	if err != nil {
		return nil, err
	}
	defer clearSensitive(crypter.aesKey)
	defer clearSensitive(crypter.hmacKey)

	c, err := crypter.Encrypt(data)
	if err != nil {
		return nil, err
	}

	ck, err := MarshalCrypterProto(crypter)
	if err != nil {
		return nil, err
	}
	// TODO: because ck.Key is marshaled via proto.Marshal,
	// it may make copies, and thus is not necessarily secure
	defer ZeroBytes(ck.Key)

	ckb, err := proto.Marshal(ck)
	if err != nil {
		return nil, err
	}
	// TODO: same problem as ck.Key
	defer ZeroBytes(ckb)

	priv, pub, err := tpm2.AssistSeal(tt.rw, rh, ckb,
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
	rh, err := tt.loadRootContext()
	if err != nil {
		return nil, "", err
	}
	defer tpm2.FlushContext(tt.rw, rh)

	sh, policy_digest, err := tt.loadSessionContext()
	if err != nil {
		return nil, "", errors.New("Can't load root key")
	}
	defer tpm2.FlushContext(tt.rw, sh)

	// The sealed data is a HybridSealedData.
	var h HybridSealedData
	if err := proto.Unmarshal(sealed, &h); err != nil {
		return nil, "", err
	}

	// Decode buffer containing pub and priv blobs
	pub, priv := DecodeTwoBytes(h.SealedKey)
	unsealed, nonce, err := tpm2.AssistUnsealKey(tt.rw, sh,
		rh, pub, priv, "", tt.password, policy_digest)
	if err != nil {
		return nil, "", err
	}
	defer clearSensitive(unsealed)
	defer clearSensitive(nonce)

	// TODO: tpm2 unseal returns a byte array that could be copied by GC,
	// so need to do something about that..
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

func (s *TPM2Tao) InitCounter(label string, c int64) error {
	fmt.Printf("TPM2Tao.InitCounter\n")
	// TODO(jlm): Change this?
	if uint32(s.nvHandle) != 0 {
		return nil
	}
	// TODO: make this more general?
	var err error
	s.nvHandle, err = tpm2.GetNvHandle(1000)
	if err != nil {
		return err
	}
	s.authString = "01020304"

	return tpm2.InitCounter(s.rw, s.nvHandle, s.authString)
}

func (s *TPM2Tao) GetCounter(label string) (int64, error) {
	fmt.Printf("TPM2Tao.GetCounter\n")
	err := s.InitCounter(label, int64(0))
	if err != nil {
		return int64(0), err
	}
	return tpm2.GetCounter(s.rw, s.nvHandle, s.authString)
}

// Note:  Tpm2 counters work differently from other counters.  On startup, you
// can't read a counter value before you initialize it which you do by incrementing
// it.  What we do is use the (countvalue+1)/2 as the counter in RollbackSeal and Unseal.
// When you seal, // if the current counter is odd, you bump it twice and use the
// value (countvalue+1)/2 in the counter slot.  If the counter is even, you bump by 1.
// You also need to reseal the tpm keys when you startup since you may shutdown
// before a RollbackSeal and your key will bump by two and give the wrong counter value.
// Programmers need to know that the value returned by GetCounter is thus different from
// the value in the sealed Rollback blob.

func (s *TPM2Tao) RollbackProtectedSeal(label string, data []byte, policy string) ([]byte, error) {
	_ = s.InitCounter(label, int64(0))
	c, err := tpm2.GetCounter(s.rw, s.nvHandle, s.authString)
	if err != nil {
		return nil, err
	}
	err = tpm2.IncrementNv(s.rw, s.nvHandle, s.authString)
	if err != nil {
		return nil, err
	}
	if (c % 2) != 0 {
		err = tpm2.IncrementNv(s.rw, s.nvHandle, s.authString)
		if err != nil {
			return nil, err
		}
	}
	c, err = tpm2.GetCounter(s.rw, s.nvHandle, s.authString)
	if err != nil {
		return nil, err
	}
	cmp_ctr := (c + 1) / 2
	sd := new(RollbackSealedData)
	sd.Entry = new(RollbackEntry)
	programName := s.name.String()
	sd.Entry.HostedProgramName = &programName
	sd.Entry.EntryLabel = &label
	sd.Entry.Counter = &cmp_ctr
	sd.ProtectedData = data
	toSeal, err := proto.Marshal(sd)
	if err != nil {
		return nil, errors.New("Can't marshal tpm2 rollback data")
	}
	sealed, err := s.Seal(toSeal, policy)
	return sealed, err
}

func (s *TPM2Tao) RollbackProtectedUnseal(sealed []byte) ([]byte, string, error) {
	_ = s.InitCounter("", int64(0))
	unsealed, policy, err := s.Unseal(sealed)
	if err != nil {
		return nil, policy, err
	}
	c, err := tpm2.GetCounter(s.rw, s.nvHandle, s.authString)
	if err != nil {
		return nil, policy, err
	}
	cmp_ctr := (c + 1) / 2
	var sd RollbackSealedData
	err = proto.Unmarshal(unsealed, &sd)
	if err != nil {
		return nil, policy, err
	}
	if sd.Entry == nil || sd.Entry.Counter == nil || *sd.Entry.Counter != cmp_ctr {
		return nil, policy, errors.New("tpm2tao.RollbackProtectedUnseal bad counter")
	}
	return sd.ProtectedData, policy, nil
}

// extractPCRs gets the PCRs from a tpm principal.
func extractTpm2PCRs(p auth.Prin) ([]int, []byte, error) {
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

// extractTPM2Key gets an RSA public key from the TPM key material.
func extractTPM2Key(material []byte) (*rsa.PublicKey, error) {
	return extractTPMKey(material) // same key format as TPM 1.2
}

// Input: Der encoded endorsement cert and handles
// quote key is certified key unlike in the tpm2.go library
// Returns ProgramCertRequestMessage
func Tpm2ConstructClientRequest(rw io.ReadWriter, derEkCert []byte, pcrs []int,
	qh tpm2.Handle, parentPassword string, ownerPassword string,
	keyName string) (*tpm2.ProgramCertRequestMessage, error) {

	// Generate Request
	request := new(tpm2.ProgramCertRequestMessage)
	request.ProgramKey = new(tpm2.ProgramKeyParameters)
	request.EndorsementCertBlob = derEkCert
	req_id := "001"
	request.RequestId = &req_id

	// Quote key
	keyBlob, tpm2QuoteName, _, err := tpm2.ReadPublic(rw, qh)
	if err != nil {
		return nil, err
	}
	rsaQuoteParams, err := tpm2.DecodeRsaBuf(keyBlob)
	if err != nil {
		return nil, err
	}

	modSize := int32(rsaQuoteParams.Mod_sz)

	keyType := "rsa"
	request.ProgramKey.ProgramName = &keyName
	request.ProgramKey.ProgramKeyType = &keyType
	request.ProgramKey.ProgramBitModulusSize = &modSize

	request.ProgramKey.ProgramKeyExponent = []byte{0, 1, 0, 1}
	request.ProgramKey.ProgramKeyModulus = rsaQuoteParams.Modulus
	serializedProgramKey := proto.CompactTextString(request.ProgramKey)
	sha1Hash := sha1.New()
	sha1Hash.Write([]byte(serializedProgramKey))
	hashProgramKey := sha1Hash.Sum(nil)

	sigAlg := uint16(tpm2.AlgTPM_ALG_NULL)
	attest, sig, err := tpm2.Quote(rw, qh, parentPassword, ownerPassword,
		hashProgramKey, pcrs, sigAlg)
	if err != nil {
		return nil, err
	}

	// Quote key info.
	request.QuoteKeyInfo = new(tpm2.QuoteKeyInfoMessage)
	request.QuoteKeyInfo.Name = tpm2QuoteName
	request.QuoteKeyInfo.PublicKey = new(tpm2.PublicKeyMessage)
	request.QuoteKeyInfo.PublicKey.RsaKey = new(tpm2.RsaPublicKeyMessage)
	request.QuoteKeyInfo.PublicKey.RsaKey.KeyName = &keyName

	var encAlg string
	var hashAlg string
	if rsaQuoteParams.Enc_alg == tpm2.AlgTPM_ALG_RSA {
		encAlg = "rsa"
	} else {
		return nil, err
	}
	if rsaQuoteParams.Hash_alg == tpm2.AlgTPM_ALG_SHA1 {
		hashAlg = "sha1"
	} else if rsaQuoteParams.Hash_alg == tpm2.AlgTPM_ALG_SHA256 {
		hashAlg = "sha256"
	} else {
		return nil, err
	}
	request.QuoteKeyInfo.PublicKey.KeyType = &encAlg
	request.QuoteKeyInfo.PublicKey.RsaKey.BitModulusSize = &modSize
	request.QuoteKeyInfo.PublicKey.RsaKey.Modulus = rsaQuoteParams.Modulus
	request.QuoteSignAlg = &encAlg
	request.QuoteSignHashAlg = &hashAlg

	request.ProgramKey = new(tpm2.ProgramKeyParameters)
	request.ProgramKey.ProgramName = &keyName
	request.ProgramKey.ProgramKeyType = &encAlg
	request.ProgramKey.ProgramBitModulusSize = &modSize
	request.ProgramKey.ProgramKeyModulus = rsaQuoteParams.Modulus

	request.QuotedBlob = attest
	request.QuoteSignature = sig
	return request, nil
}

// Output is der encoded Program Cert
func Tpm2ClientDecodeServerResponse(rw io.ReadWriter,
	protectorHandle tpm2.Handle,
	quoteHandle tpm2.Handle, password string,
	response tpm2.ProgramCertResponseMessage) ([]byte, error) {
	certBlob := append(response.IntegrityHMAC, response.EncIdentity...)
	certInfo, err := tpm2.ActivateCredential(rw, quoteHandle,
		protectorHandle, password, "", certBlob, response.Secret)
	if err != nil {
		return nil, err
	}

	// Decrypt cert.
	_, out, err := tpm2.EncryptDataWithCredential(false,
		uint16(tpm2.AlgTPM_ALG_SHA1),
		certInfo, response.EncryptedCert, response.EncryptedCertHmac)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Return attest certificate
func (tt *TPM2Tao) Tpm2Certify(network, addr string, keyName string) ([]byte, error) {
	// Establish connection wtih the CA.
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	rk, err := tt.loadRootContext()
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(tt.rw, rk)

	qh, err := tt.loadQuoteContext()
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(tt.rw, qh)

	ms := util.NewMessageStream(conn)
	programCertMessage, err := Tpm2ConstructClientRequest(tt.rw,
		tt.rootCert, tt.pcrs,
		qh, "", tt.password, keyName)
	_, err = ms.WriteMessage(programCertMessage)
	if err != nil {
		return nil, err
	}

	var resp tpm2.ProgramCertResponseMessage
	err = ms.ReadMessage(&resp)
	if err != nil {
		return nil, err
	}
	attestCert, err := Tpm2ClientDecodeServerResponse(tt.rw, rk, qh,
		tt.password, resp)
	return attestCert, nil
}
