package main

import (
	"cloudproxy/tao"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func hostTaoDemo() error {
	if tao.Host == nil {
		return errors.New("No host Tao available")
	}

	var err error

	var name string
	name, err = tao.Host.GetTaoName()
	if err != nil {
		return err
	}
	fmt.Printf("My root name is %s\n", name)

	args := make([]string, len(os.Args))
	for index, arg := range os.Args {
		args[index] = strconv.Quote(arg)
	}
	subprin := "Args(" + strings.Join(args, ", ") + ")"
	err = tao.Host.ExtendTaoName(subprin)
	if err != nil {
		return err
	}

	name, err = tao.Host.GetTaoName()
	if err != nil {
		return err
	}
	fmt.Printf("My full name is %s\n", name)

	var random []byte
	random, err = tao.Host.GetRandomBytes(10)
	if err != nil {
		return err
	}
	fmt.Printf("Random bytes  : % x\n", random)

	var secret []byte
	secret, err = tao.Host.GetSharedSecret(10, tao.SharedSecretPolicyDefault)
	if err != nil {
		return err
	}
	fmt.Printf("Shared secret : % x\n", secret)

	var sealed []byte
	sealed, err = tao.Host.Seal(random, tao.SealPolicyDefault)
	if err != nil {
		return err
	}
	fmt.Printf("Sealed bytes  : % x\n", sealed)

	var unsealed []byte
	var policy string
	unsealed, policy, err = tao.Host.Unseal(sealed)
	if err != nil {
		return err
	}
	if policy != tao.SealPolicyDefault {
		return errors.New("Unexpected policy on unseal")
	}
	fmt.Printf("Unsealed bytes: % x\n", unsealed)

	return nil
}

func main() {
	fmt.Printf("Go Tao Demo\n")

	err := hostTaoDemo()
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}
}
