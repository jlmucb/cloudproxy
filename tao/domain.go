// Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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
	"io"
	"os"
	"path"

	"code.google.com/p/gcfg"

	"github.com/jlmucb/cloudproxy/tao/auth"
	"github.com/jlmucb/cloudproxy/util"
)

// Domain manages domain-wide authorization policies and configuration for a
// single Tao administrative domain. Configuration includes a name, domain guard
// type, ACLs or other guard-specific policy data, and a key pair for signing
// policy data.
//
// Except for a password used to encrypt the policy private key, top-level
// configuration data for Domain is stored in a text file, typically named
// "tao.config". This configuration file contains the locations of all other
// files and directories, e.g. configuration files for the domain guard. File
// and directory paths within the tao.config file are relative to the location
// of the tao.config file itself.
type Domain struct {
	Config     DomainConfig
	ConfigPath string
	Keys       *Keys
	Guard      Guard
}

// DomainConfig holds the presistent configuration data for a domain.
type DomainConfig struct {

	// Policy-agnostic configuration
	Domain struct {
		// Name of the domain
		Name string
		// Path to the password-protected signing key
		PolicyKeysPath string
		// Type of guard to use for domain-wide policy decisions
		GuardType string
	}

	// Details used for the domain signing key x509 certificate
	X509Details X509Details

	// Policy-specific configuration (optional)
	ACLGuard ACLGuardConfig

	// Policy-specific configuration (optional)
	DatalogGuard DatalogGuardConfig
}

// Print prints the configuration to out.
func (cfg DomainConfig) Print(out io.Writer) error {
	return util.PrintAsGitConfig(out, cfg, "Tao Domain Configuration file")
}

// SetDefaults sets each blank field of cfg to a reasonable default value.
func (cfg *DomainConfig) SetDefaults() {
	if cfg.Domain.Name == "" {
		cfg.Domain.Name = "Tao example domain"
	}
	if cfg.Domain.PolicyKeysPath == "" {
		cfg.Domain.PolicyKeysPath = "policy_keys"
	}
	if cfg.Domain.GuardType == "" {
		cfg.Domain.GuardType = "DenyAll"
	}
	if cfg.X509Details.CommonName == "" {
		cfg.X509Details.CommonName = cfg.Domain.Name
	}
}

// String returns the name of the domain.
func (d *Domain) String() string {
	return d.Config.Domain.Name
}

// Subprincipal returns a subprincipal suitable for contextualizing a program.
func (d *Domain) Subprincipal() auth.SubPrin {
	e := auth.PrinExt{
		Name: "Domain",
		Arg: []auth.Term{
			d.Keys.VerifyingKey.ToPrincipal(),
			auth.Str(d.Config.Domain.GuardType),
		},
	}
	return auth.SubPrin{e}
}

// CreateDomain initializes a new Domain, writing its configuration files to
// a directory. This creates the directory if needed, creates a policy key pair
// (encrypted with the given password when stored on disk), and initializes a
// default guard of the appropriate type if needed. Any parameters left empty in
// cfg will be set to reasonable default values.
func CreateDomain(cfg DomainConfig, configPath string, password []byte) (*Domain, error) {
	(&cfg).SetDefaults()

	configDir := path.Dir(configPath)
	err := os.MkdirAll(configDir, 0777)
	if err != nil {
		return nil, err
	}

	keypath := path.Join(configDir, cfg.Domain.PolicyKeysPath)
	keys, err := NewOnDiskPBEKeys(Signing, password, keypath, NewX509Name(cfg.X509Details))
	if err != nil {
		return nil, err
	}

	var guard Guard
	switch cfg.Domain.GuardType {
	case "ACLs":
		guard = NewACLGuard(cfg.ACLGuard)
	case "Datalog":
		guard, err = NewDatalogGuard(keys.VerifyingKey, cfg.DatalogGuard)
		if err != nil {
			return nil, err
		}
	case "AllowAll":
		guard = LiberalGuard
	case "DenyAll":
		guard = ConservativeGuard
	default:
		return nil, newError("unrecognized guard type: %s", cfg.Domain.GuardType)
	}

	d := &Domain{cfg, configPath, keys, guard}
	err = d.Save()
	if err != nil {
		return nil, err
	}
	return d, nil
}

// Save writes all domain configuration and policy data.
func (d *Domain) Save() error {
	file, err := util.CreatePath(d.ConfigPath, 0777, 0666)
	if err != nil {
		return err
	}
	d.Config.Print(file)
	file.Close()
	return d.Guard.Save(d.Keys.SigningKey)
}

// LoadDomain initialize a Domain from an existing configuration file. If
// password is nil, the object will be "locked", meaning that the policy private
// signing key will not be available, new ACL entries or attestations can not be
// signed, etc. Otherwise, password will be used to unlock the policy private
// signing key.
func LoadDomain(configPath string, password []byte) (*Domain, error) {
	var cfg DomainConfig
	err := gcfg.ReadFileInto(&cfg, configPath)
	if err != nil {
		return nil, err
	}

	configDir := path.Dir(configPath)
	keypath := path.Join(configDir, cfg.Domain.PolicyKeysPath)
	keys, err := NewOnDiskPBEKeys(Signing, password, keypath, nil)
	if err != nil {
		return nil, err
	}

	var guard Guard
	switch cfg.Domain.GuardType {
	case "ACLs":
		var err error
		guard, err = LoadACLGuard(keys.VerifyingKey, cfg.ACLGuard)
		if err != nil {
			return nil, err
		}
	case "Datalog":
		var err error
		datalogGuard, err := NewDatalogGuard(keys.VerifyingKey, cfg.DatalogGuard)
		if err != nil {
			return nil, err
		}
		if err := datalogGuard.ReloadIfModified(); err != nil {
			return nil, err
		}
		guard = datalogGuard
	case "AllowAll":
		guard = LiberalGuard
	case "DenyAll":
		guard = ConservativeGuard
	}
	//TODO (important!): Need to modify tao name to reflect policy key

	return &Domain{cfg, configPath, keys, guard}, nil
}

// ExtendTaoDomain uses a Domain's Verifying key to extend the Tao with a
// subprincipal PolicyKey([...]).
func (d *Domain) ExtendTaoName(tao Tao) error {
	if d.Keys == nil || d.Keys.VerifyingKey == nil {
		return newError("no verifying key to use for name extension")
	}

	// This is a key Prin with type "key" and auth.Bytes as its Term
	p := d.Keys.VerifyingKey.ToPrincipal()
	b, ok := p.Key.(auth.Bytes)
	if !ok {
		return newError("couldn't get an auth.Bytes value from the key")
	}

	sp := auth.SubPrin{
		auth.PrinExt{
			Name: "PolicyKey",
			Arg:  []auth.Term{b},
		},
	}

	return tao.ExtendTaoName(sp)
}
