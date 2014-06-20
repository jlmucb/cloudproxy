package tao

import (
	key "github.com/dgryski/dkeyczar"
)

var _ = key.NewKeyManager

type KeyType int
const (
	Signing KeyType = 1 << iota
	Crypting KeyType = 1 << iota
	KeyDeriving KeyType = 1 << iota
)

type Keys interface {
	InitNonHosted(password string) error
	InitHosted(t Tao, policy string) error
	PrincipalName() string
	Delegation() *Attestation
}

func NewTempKeys(nickname string, kt KeyType, t Tao) Keys {
	return nil	
}

func NewHostedKeys(t Tao, policy string) Keys {
	return nil
}

func NewFileKeys(path, nickname string, kt KeyType) Keys {
	return nil
}
