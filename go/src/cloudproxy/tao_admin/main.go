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

package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"cloudproxy/tao"
	"cloudproxy/tao/auth"
	"cloudproxy/util"
)

// common options
var configPath = flag.String("config_path", "tao.config", "Location of tao domain configuration.")
var pass = flag.String("pass", "", "Password for unlocking policy private key.")
var quiet = flag.Bool("quiet", false, "Be more quiet.")
var show = flag.Bool("show", false, "Show info when done.")
var host = flag.String("host", "", "The principal name of the host where programs will execute.")

// initializing a new domain
var create = flag.Bool("create", false, "Create a new domain configuration.")
var name = flag.String("name", "", "Name for a new configuration.")
var guard = flag.String("guard", "TrivialLiberalGuard", "Name of guard: ACLs, Datalog, etc.")

// execution policy changes
var canExecute = flag.String("canexecute", "", "Path of a program to be authorized to execute.")
var retractCanExecute = flag.String("retractcanexecute", "", "Path of a program to retract authorization to execute.")

// arbitrary policy changes
var add = flag.String("add", "", "A policy rule to be added.")
var retract = flag.String("retract", "", "A policy rule to be retracted.")
var clear = flag.Bool("clear", false, "Clear all policy rules before other changes.")
var query = flag.String("query", "", "A policy query to be checked.")

// misc. utilities
var getProgramHash = flag.String("getprogramhash", "", "Path of program to be hashed.")

func main() {
	help := "Administrative utility for Tao Domain.\n"
	help += "Usage: %[1]s [options] -create [-name name]\n"
	help += "%[1]s [options] -(retractcanexecute|canexecute) progpath\n"
	help += "%[1]s [options] -(add|retract|query) rule\n"
	help += "%[1]s [options] -clear\n"
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, help, os.Args[0])
		flag.PrintDefaults()
	}
	util.UseEnvFlags("GLOG", "TAO", "TAO_ADMIN")
	flag.Parse()

	var noise io.Writer
	if *quiet {
		noise = ioutil.Discard
	} else {
		noise = os.Stdout
	}

	var domain *tao.Domain
	var err error

	didWork := false

	if *create {
		didWork = true
		if len(*pass) == 0 {
			log.Fatal("password is required")
		}
		fmt.Fprintf(noise, "Initializing new configuration in: %s\n", *configPath)
		var cfg tao.DomainConfig
		if *name != "" {
			cfg.Domain.Name = *name
			cfg.X509Details.CommonName = *name
		}
		if *guard != "" {
			cfg.Domain.GuardType = *guard
		}

		domain, err = tao.CreateDomain(cfg, *configPath, []byte(*pass))
		fatalIf(err)
	} else {
		fmt.Fprintf(noise, "Loading configuration from: %s\n", *configPath)
		domain, err = tao.LoadDomain(*configPath, []byte(*pass))
		fatalIf(err)
	}

	if *clear {
		didWork = true
		domain.Guard.Clear()
		err := domain.Save()
		fatalIf(err)
	}
	if *canExecute != "" {
		path := *canExecute
		prin := makeHostPrin(*host)
		subprin := makeProgramSubPrin(path)
		prog := prin.MakeSubprincipal(subprin)
		fmt.Fprintf(noise, "Authorizing program to execute:\n"+
			"  path: %s\n"+
			"  host: %s\n"+
			"  name: %s\n", path, prin, subprin)
		err := domain.Guard.Authorize(prog, "Execute", nil)
		fatalIf(err)
		didWork = true
	}
	if *retractCanExecute != "" {
		path := *retractCanExecute
		prin := makeHostPrin(*host)
		subprin := makeProgramSubPrin(path)
		prog := prin.MakeSubprincipal(subprin)
		fmt.Fprintf(noise, "Retracting program authorization to execute:\n"+
			"  path: %s\n"+
			"  host: %s\n"+
			"  name: %s\n", path, prin, subprin)
		err := domain.Guard.Retract(prog, "Execute", nil)
		fatalIf(err)
		didWork = true
	}
	if *add != "" {
		fmt.Fprintf(noise, "Adding policy rule: %s\n", *add)
		err := domain.Guard.AddRule(*add)
		fatalIf(err)
		err = domain.Save()
		fatalIf(err)
		didWork = true
	}
	if *retract != "" {
		fmt.Fprintf(noise, "Retracting policy rule: %s\n", *retract)
		err := domain.Guard.RetractRule(*retract)
		fatalIf(err)
		err = domain.Save()
		fatalIf(err)
		didWork = true
	}
	if *query != "" {
		fmt.Fprintf(noise, "Querying policy guard: %s\n", *query)
		ok, err := domain.Guard.Query(*query)
		fatalIf(err)
		if ok {
			fmt.Printf("Policy supports query.\n")
		} else {
			fmt.Printf("Policy rejects query.\n")
		}
		didWork = true
	}
	if *getProgramHash != "" {
		path := *getProgramHash
		subprin := makeProgramSubPrin(path)
		fmt.Println(subprin)
		didWork = true
	}
	if *show || !didWork {
		domain.Config.Print(os.Stdout)
	}
}

func hash(path string) []byte {
	file, err := os.Open(path)
	fatalIf(err)
	hasher := sha256.New()
	_, err = io.Copy(hasher, file)
	fatalIf(err)
	return hasher.Sum(nil)
}

func makeHostPrin(host string) auth.Prin {
	// Here we rely on there being an env var for the host name. We could also use
	// a different env var to contact a host and ask its name. That would require
	// the host to be running, though.
	if host == "" {
		host = os.Getenv("GOOGLE_TAO_LINUX")
	}
	if host == "" {
		log.Fatal("No tao host: set $GOOGLE_TAO_LINUX or use -host option")
	}
	var prin auth.Prin
	_, err := fmt.Sscanf(host, "%v", &prin)
	fatalIf(err)
	return prin
}

func makeProgramSubPrin(prog string) auth.SubPrin {
	// BUG(kwalsh) This assumes no IDs, and it assumes linux hosts.
	id := uint(0)
	h := hash(prog)
	return tao.FormatHostedProgramSubprin(id, h)
}

func fatalIf(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
