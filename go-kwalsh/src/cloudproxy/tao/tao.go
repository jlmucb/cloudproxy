package tao

import (
	"fmt"
	"os"
)

const (
	HostTaoEnvVar = "GOOGLE_HOST_TAO"

	SharedSecretPolicyDefault = "self"
	SharedSecretPolicyConservative = "few"
	SharedSecretPolicyLiberal = "any"

	SealPolicyDefault = "self"
	SealPolicyConservative = "few"
	SealPolicyLiberal = "any"
)

// Tao is the fundamental Trustworthy Computing interface provided by a host to
// its hosted programs. Each level of a system can act as a host by exporting
// the Tao interface and providing Tao services to higher-level hosted
// programs.
//
// In most cases, a hosted program will use a stub Tao that performs RPC over a
// channel to its host. The details of such RPC depend on the specific
// implementation of the host: some hosted programs may use pipes to
// communicate with their host, others may use sockets, etc.
type Tao interface {
	// GetTaoName returns the Tao principal name assigned to this hosted
	// program.
	GetTaoName() (name string, err error)

	/// ExtendTaoName irreversibly extend the Tao principal name of this hosted
	/// program.
	ExtendTaoName(subprin string) error

	// GetRandomBytes returns a slice of n random bytes.
	GetRandomBytes(n int) (bytes []byte, err error)

	// GetSharedSecret returns a slice of n secret bytes.
	GetSharedSecret(n int, policy string) (bytes []byte, err error)

	// Attest requests the Tao host sign a Statement on behalf of this hosted program.
	Attest(stmt *Statement) (*Attestation, error)

	// Seal encrypts data so only certain hosted programs can unseal it.
	Seal(data []byte, policy string) (sealed []byte, err error)

	// Decrypt data that has been sealed by the Seal() operation, but only
	// if the policy specified during the Seal() operation is satisfied.
	Unseal(sealed []byte) (data []byte, policy string, err error)

	// Get most recent error message, if any.
	GetRecentErrorMessage() string

	// Clear the most recent error message and return the previous value, if any.
	ResetRecentErrorMessage() string
}

var hostTao Tao

func Host() Tao {
	if hostTao != nil {
		return hostTao
	}
	s := os.Getenv(HostTaoEnvVar)
	if s == "" {
		fmt.Printf("Missing tao env\n")
		return nil
	}
	hostTao := DeserializeTaoRPC(s)
	if hostTao != nil {
		fmt.Printf("Got serialized TaoRPC\n")
	} else {
		fmt.Printf("Did not get message channel\n")
	}
	return hostTao
}
