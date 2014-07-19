package tpm

import (
    "encoding/base64"
    "os"
    "testing"
)

func TestEncoding(t *testing.T) {
	sel := &PCRSelection{100, [3]byte{1, 2, 3}}
	d := make([]byte, 5)
	if _, err := EncodeTPMStruct(d, sel); err != nil {
        t.Fatal("Couldn't encode the struct:", err)
	}

    res := []byte{0, 100, 1, 2, 3}
    for i := range res {
        if res[i] != d[i] {
            t.Fatal("Invalid encoding")
        }
    }

	var s PCRSelection
	if _, err := DecodeTPMStruct(&s, d); err != nil {
		t.Fatal("Couldn't decode the struct:", err)
	}

    if s.Size != sel.Size {
        t.Fatal("Invalid decoded size")
    }

    for i := range s.Mask {
        if s.Mask[i] != sel.Mask[i] {
            t.Fatal("Invalid decoded mask")
        }
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
