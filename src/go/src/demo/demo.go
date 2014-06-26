package main

import (
	"fmt"
	"tao"
)

func main() {
	fmt.Printf("Go Tao Demo\n")
	host := tao.Host()
	if host == nil {
		fmt.Printf("Can't get host Tao\n")
		return
	}

	var err error

	var name string
	name, err = host.GetTaoName()
	if err != nil {
		fmt.Printf("Can't get my name\n")
		return
	}
	fmt.Printf("My name is %s\n", name)

	var random []byte
	random, err = host.GetRandomBytes(10)
	if err != nil {
		fmt.Printf("Can't get random bytes\n")
		return
	}
	fmt.Printf("Random bytes  : % x\n", random)

	var sealed []byte
	sealed, err = host.Seal(random, tao.SealPolicyDefault)
	if err != nil {
		fmt.Printf("Can't seal bytes\n")
		return
	}
	fmt.Printf("Sealed bytes  : % x\n", sealed)

	var unsealed []byte
	var policy string
	unsealed, policy, err = host.Unseal(sealed)
	if err != nil {
		fmt.Printf("Can't unseal bytes\n")
		return
	}
	if policy != tao.SealPolicyDefault {
		fmt.Printf("Unexpected policy on unseal\n")
		return
	}
	fmt.Printf("Unsealed bytes: % x\n", unsealed)

}
