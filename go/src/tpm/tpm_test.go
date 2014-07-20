package tpm

import (
	"encoding/hex"
	"os"
	"testing"
)

func TestEncoding(t *testing.T) {
	ch := CommandHeader{tagRQUCommand, 0, ordOIAP}
	var c uint32 = 137
	in := []interface{}{c}

	b, err := Pack(ch, in)
	if err != nil {
		t.Fatal("Couldn't pack the bytes:", err)
	}

	var hdr CommandHeader
	var size uint32
	out := []interface{}{&hdr, &size}
	if err := Unpack(b, out); err != nil {
		t.Fatal("Couldn't unpack the packed bytes")
	}

	if size != 137 {
		t.Fatal("Got the wrong size back")
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

	resStr := hex.EncodeToString(res)
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

	s := hex.EncodeToString(b)
	t.Logf("Got random bytes %s\n", s)
}
