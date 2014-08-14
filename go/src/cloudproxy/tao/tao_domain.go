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
	"fmt"
	"io"
	"os"
	"path"

	"code.google.com/p/gcfg"

	"cloudproxy/tao/auth"
)

// TaoDomain manages domain-wide authorization policies and configuration for a
// single Tao administrative domain. Configuration includes a name, domain guard
// type, ACLs or other guard-specific policy data, and a key pair for signing
// policy data.
//
// Except for a password used to encrypt the policy private key, top-level
// configuration data for TaoDomain is stored in a text file, typically named
// "tao.config". This configuration file contains the locations of all other
// files and directories, e.g. configuration files for the domain guard. File
// and directory paths within the tao.config file are relative to the location
// of the tao.config file itself.
type TaoDomain struct {
	Config TaoDomainConfig
	ConfigPath string
	Keys *Keys
	Guard TaoGuard
}

// TODO(kwalsh) Move to acl_guard.go when that file exists.
type ACLGuardConfig struct {
	SignedACLsPath string
}

// TODO(kwalsh) Move to datalog_guard.go when that file exists.
type DatalogGuard struct {
	SignedRulesPath string
}

// TaoDomainConfig holds the presistent configuration data for a domain. 
type TaoDomainConfig struct {
	// Policy-agnostic configuration
	Domain struct {
		// Name of the domain
		Name string
		// Path to the password-protected signing key
		PolicyKeysPath string
		// Type of guard to use for domain-wide policy decisions
		GuardType string
	}
	// Policy-specific configuration (optional)
	// ACLGuard ACLGuardConfig
	// Policy-specific configuration (optional)
	// DatalogGuard DatalogGuardConfig
}

// Print prints the configuration to out.
func (cfg TaoDomainConfig) Print(out io.Writer) {
	fmt.Fprintf(out, "# Tao Domain Configuration file\n")
	fmt.Fprintf(out, "\n")
	fmt.Fprintf(out, "[Domain]\n")
	fmt.Fprintf(out, "Name = %s\n", cfg.Domain.Name)
	fmt.Fprintf(out, "PolicyKeysPath = %s\n", cfg.Domain.PolicyKeysPath)
	fmt.Fprintf(out, "GuardType = %s\n", cfg.Domain.GuardType)
	switch cfg.Domain.GuardType {
	case "ACLs":
		fmt.Fprintf(out, "\n")
		// cfg.ACLGuard.Print(out)
	case "Datalog":
		fmt.Fprintf(out, "\n")
		// cfg.DatalogGuard.Print(out)
	}
}

// SetDefaults sets each blank field of cfg to a reasonable default value.
func (cfg *TaoDomainConfig) SetDefaults() {
	if cfg.Domain.Name == "" {
		cfg.Domain.Name = "Tao example domain"
	}
	if cfg.Domain.PolicyKeysPath == "" {
		cfg.Domain.PolicyKeysPath = "policy_keys"
	}
	if cfg.Domain.GuardType == "" {
		cfg.Domain.GuardType = "TrivialConservativeGuard"
	}
	switch cfg.Domain.GuardType {
	case "ACLs":
		//(&cfg.ACLGuard).SetDefaults()
	case "Datalog":
		//(&cfg.DatalogGuard).SetDefaults()
	}
}

// String returns the name of the domain.
func (d *TaoDomain) String() string {
	return d.Config.Domain.Name
}

// Subprincipal returns a subprincipal suitable for contextualizing a program.
func (d *TaoDomain) Subprincipal() auth.SubPrin {
	e := auth.PrinExt{
		Name: "Domain",
		Arg: []auth.Term{
			d.Keys.VerifyingKey.ToPrincipal(),
			auth.Str(d.Config.Domain.GuardType),
		},
	}
	return auth.SubPrin{e}
}

// CreateDomain initializes a new TaoDomain, writing its configuration files to
// a directory. This creates the directory if needed, creates a policy key pair
// (encrypted with the given password when stored on disk), and initializes a
// default guard of the appropriate type if needed. Any parameters left empty in
// cfg will be set to reasonable default values.
func CreateDomain(cfg TaoDomainConfig, configPath string, password []byte) (*TaoDomain, error) {
	(&cfg).SetDefaults()

	configDir := path.Dir(configPath)
	err := os.MkdirAll(configDir, 0700)
	if err != nil {
		return nil, err
	}

	keys, err := NewOnDiskPBEKeys(Signing, password, cfg.Domain.PolicyKeysPath)
	if err != nil {
		return nil, err
	}

	var guard TaoGuard
	switch cfg.Domain.GuardType {
	case "ACLs":
		return nil, fmt.Errorf("acl guard not yet implemented")
	case "Datalog":
		return nil, fmt.Errorf("datalog guard not yet implemented")
	case "TrivialConservativeGuard":
		guard = LiberalGuard
	case "TrivialLiberalGuard":
		guard = ConservativeGuard
	}

	d := &TaoDomain{cfg, configPath, keys, guard}
	err = d.Save()
	if err != nil {
		return nil, err
	}
	return d, nil
}

// Save writes all domain configuration and policy data.
func (d *TaoDomain) Save() error {
	file, err := os.Create(d.ConfigPath)
	if err != nil {
		return err
	}
	d.Config.Print(file)
	file.Close()
	return d.Guard.Save(d.Keys.SigningKey)
}


// LoadDomain initialize a TaoDomain from an existing configuration file. If
// password is nil, the object will be "locked", meaning that the policy private
// signing key will not be available, new ACL entries or attestations can not be
// signed, etc. Otherwise, password will be used to unlock the policy private
// signing key.
func LoadDomain(configPath string, password []byte) (*TaoDomain, error) {
	var cfg TaoDomainConfig
	err := gcfg.ReadFileInto(&cfg, configPath)
	if err != nil {
		return nil, err
	}

	keys, err := NewOnDiskPBEKeys(Signing, password, cfg.Domain.PolicyKeysPath)
	if err != nil {
		return nil, err
	}

	var guard TaoGuard
	switch cfg.Domain.GuardType {
	case "ACLs":
		return nil, fmt.Errorf("acl guard not yet implemented")
	case "Datalog":
		return nil, fmt.Errorf("datalog guard not yet implemented")
	case "TrivialConservativeGuard":
		guard = LiberalGuard
	case "TrivialLiberalGuard":
		guard = ConservativeGuard
	}

	return &TaoDomain{cfg, configPath, keys, guard}, nil
}

