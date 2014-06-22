package main

import (
	"fmt"
	"net/rpc"
	"os"
  "time"

	"cloudproxy/tao"
	"cloudproxy/util"

  "code.google.com/p/goprotobuf/proto"
)

func main() {
	fmt.Println("Hosted program started")

	// This program expects to get pipes as file descriptors 3 and 4 (R and W, respectively)
	var clientRWC util.PairReadWriteCloser
	clientRWC.R = os.NewFile(3, "")
	clientRWC.W = os.NewFile(4, "")

	t := &tao.TaoClient{
		Parent: rpc.NewClient(clientRWC),
	}

	b := make([]byte, 10)
	err := t.GetRandomBytes(b)
	if err != nil {
		fmt.Println("Couldn't get random bytes:", err)
		return
	}

	fmt.Println("Got 10 random bytes")

  // Seal, Unseal, and Attest to the bytes
  sealed, err := t.Seal(b, []byte(tao.SealPolicyDefault))
  if err != nil {
    fmt.Println("Couldn't seal the data:", err)
    return
  }

  unsealed, policy, err := t.Unseal(sealed)
  if err != nil {
    fmt.Println("Couldn't unseal the data:", err)
    return
  }

  if string(policy) != tao.SealPolicyDefault {
    fmt.Println("Invalid policy returned by the Tao")
    return
  }

  if len(unsealed) != len(b) {
    fmt.Println("Invalid unsealed length")
    return
  }

  for i, v := range unsealed {
    if v != b[i] {
      fmt.Printf("Incorrect value returned at byte %d\n", i)
      return
    }
  }

  s := &tao.Statement{
    // TODO(tmroeder): Issuer, Time, and Expiration are required, but they
    // should be optional.
    Issuer: proto.String("test"),
    Time: proto.Int64(time.Now().UnixNano()),
    Expiration: proto.Int64(time.Now().UnixNano() + 100),
    Delegate: proto.String(string(b)),
  }

  _, err = t.Attest(s)
  if err != nil {
    fmt.Println("Couldn't attest to the bytes:", err)
    return
  }

  fmt.Println("All actions worked correctly")
	return
}
