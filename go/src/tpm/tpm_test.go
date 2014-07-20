package tpm

import (
	"encoding/base64"
	"os"
	"testing"
)

func TestEncoding(t *testing.T) {
	in := []interface{}{&CommandHeader{TagRQUCommand, 0, OrdOIAP}}

	b, err := Pack(in)
	if err != nil {
		t.Fatal("Couldn't pack the bytes:", err)
	}

	var hdr CommandHeader
	out := []interface{}{&hdr}
	if err := Unpack(b, out); err != nil {
		t.Fatal("Couldn't unpack the packed bytes")
	}
}

func TestReadPCR(t *testing.T) {
	// Try to read PCR 18. For this to work, you have to have access to
	// /dev/tpm0, and there has to be a TPM driver to answer requests.
	f, err := os.OpenFile("/dev/tpm0", os.O_RDWR, 0600)
	if err != nil {
		t.Fatal("Can't open /dev/tpm0 for read/write:", err)
	}

	res, err := ReadPCR(f, 18)
	if err != nil {
		t.Fatal("Couldn't read PCR 18 from the TPM:", err)
	}

	resStr := base64.StdEncoding.EncodeToString(res)
	t.Logf("Got PCR 18 value %s\n", resStr)
}

func TestGetRandom(t *testing.T) {
	// Try to get 16 bytes of randomness from the TPM.
	f, err := os.OpenFile("/dev/tpm0", os.O_RDWR, 0600)
	if err != nil {
		t.Fatal("Can't open /dev/tpm0 for read/write:", err)
	}

	b, err := GetRandom(f, 16)
	if err != nil {
		t.Fatal("Couldn't get 16 bytes of randomness from the TPM:", err)
	}

	s := base64.StdEncoding.EncodeToString(b)
	t.Logf("Got random bytes %s\n", s)
}
