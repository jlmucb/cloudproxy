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
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/google/go-tpm/tpm"
	"github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	"golang.org/x/crypto/ssh/terminal"
)

// A Value that converts 3,5,1 into []int{3, 5, 1}
type pcrs []int

func (p *pcrs) Set(val string) error {
	s := strings.Split(val, ",")
	for _, str := range s {
		v, err := strconv.Atoi(str)
		if err != nil {
			return err
		}

		*p = append(*p, v)
	}
	return nil
}

func (p *pcrs) String() string {
	s := make([]string, len([]int(*p)))
	for i, val := range *p {
		s[i] = strconv.Itoa(val)
	}
	return strings.Join(s, ",")
}

func main() {
	// The main flag that switches between operations.
	operation := flag.String("operation", "key", "The object to create ('key', 'domain', 'policy', 'user', 'principal')")

	// Common options for the operations.
	domainPath := flag.String("domain_path", "", "Location in which to create a new domain.")
	configName := flag.String("config_name", "tao.config", "Location of tao domain configuration.")
	quiet := flag.Bool("quiet", false, "Be more quiet.")

	// Flags for the 'key' option, used to create a new policy key.
	// These are also flags for the 'domain' option.
	pass := flag.String("pass", "", "Password for creating/unlocking policy private key (Testing only!).")
	configTemplate := flag.String("config_template", "", "Location of a template tao domain configuration to use.")

	// Flags for the 'policy' option, used to change and query the policy
	// rules used for principal authorization. The strings passed to these
	// rules depend on the Guard given in the domain/tao.
	canExecute := flag.String("canexecute", "", "Path of a program to be authorized to execute.")
	retractCanExecute := flag.String("retractcanexecute", "", "Path of a program to retract authorization to execute.")
	add := flag.String("add", "", "A policy rule to be added.")
	retract := flag.String("retract", "", "A policy rule to be retracted.")
	clear := flag.Bool("clear", false, "Clear all policy rules before other changes.")
	query := flag.String("query", "", "A policy query to be checked.")
	addPrograms := flag.Bool("add_programs", false, "Add the program hashes to the policy")
	addContainers := flag.Bool("add_containers", false, "Add the container hashes to the policy")
	addHost := flag.Bool("add_host", false, "Add the host to the policy")
	addVMs := flag.Bool("add_vms", false, "Add VMs to the policy")
	addLinuxHost := flag.Bool("add_linux_host", false, "Add LinuxHost to the policy")
	addGuard := flag.Bool("add_guard", false, "Add a trusted guard to the policy")

	// Flags for the 'user' option, used to create new user keys.
	userKeyDetails := flag.String("user_key_details", "", "Path to a file that contains an X509Details proto")
	userKeyPath := flag.String("user_key_path", "usercreds", "key path")
	userPass := flag.String("user_pass", "", "A password for the new user (for testing only!).")

	// Flags for the 'principal' option, used to compute principal hashes.
	principal := flag.String("principal", "program", "Type of hash to produce ('program', 'container', 'tpm', 'linux')")
	tpmPath := flag.String("tpm", "/dev/tpm0", "Path to a TPM device.")
	aikFile := flag.String("aikblob", "", "A file containing a TPM AIK.")
	keyPass := flag.String("key_pass", "", "A password to use for key-based principal (for testing only!).")

	var pcrVals pcrs
	flag.Var(&pcrVals, "pcrs", "Indices of PCRs to return.")

	help := "Administrative utility for Tao Domain.\n"
	help += "[options] = [-quiet] [-config_path tao.config]\n"
	help += "Usage: %[1]s -operation key -domain_path path -config_template file key_path\n"
	help += "%[1]s -operation domain -domain_path path -config_template file\n"
	help += "%[1]s [options] -operation policy -(retractcanexecute|canexecute) progpath\n"
	help += "%[1]s [options] -operation policy -(add|retract|query) rule\n"
	help += "%[1]s [options] -operation policy -clear\n"
	help += "%[1]s [options] -operation user -user_key_details file -user_key_path path\n"
	help += "%[1]s [options] -operation principal -principal (program|container) path\n"
	help += "%[1]s [options] -operation principal -principal tpm -tpm path -pcrs pcr1,pcr2,...,pcrN -aikblob path\n"
	help += "%[1]s [options] -operation principal -principal key path\n"
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, help, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	var noise io.Writer
	if *quiet {
		noise = ioutil.Discard
	} else {
		noise = os.Stdout
	}

	// Read the tao_admin domain template for configuration.
	var dt tao.DomainTemplate
	if *configTemplate != "" {
		pbtext, err := ioutil.ReadFile(*configTemplate)
		if err != nil {
			glog.Exit(err)
		}

		if err := proto.UnmarshalText(string(pbtext), &dt); err != nil {
			glog.Exit(err)
		}
	}

	if dt.Config == nil && (*operation == "key" || *operation == "domain" || *operation == "policy") {
		glog.Exit("must supply a template for 'key', 'domain', or 'policy' operations")
	}

	configPath := path.Join(*domainPath, *configName)
	switch *operation {
	case "key", "domain":
		pwd := getKey("password", *pass)
		if *domainPath == "" {
			glog.Exit("must supply a domain path for key and domain creation")
		}
		if dt.Config.DomainInfo.GetPolicyKeysPath() == "" {
			glog.Exit("must supply a policy_keys_path in the domain configuration")
		}

		if *operation == "key" {
			args := flag.Args()
			if len(args) != 1 {
				glog.Exit("must supply a path (relative to the domain) for the new key set")
			}
			keypath := path.Join(*domainPath, args[0])
			k, err := tao.NewOnDiskPBEKeys(tao.Signing|tao.Crypting|tao.Deriving, pwd, keypath, tao.NewX509Name(dt.Config.X509Info))
			if err != nil {
				glog.Exit(err)
			}
			fmt.Print(k.VerifyingKey.ToPrincipal())
		} else { // *operation == "domain"
			domain, err := tao.CreateDomain(*dt.Config, configPath, pwd)
			if err != nil {
				glog.Exit(err)
			}

			if dt.Config.DomainInfo.GetGuardType() == "Datalog" {
				// Add any rules specified in the domain template.
				for _, rule := range dt.DatalogRules {
					if err := domain.Guard.AddRule(rule); err != nil {
						glog.Exit(err)
					}
				}
			} else if dt.Config.DomainInfo.GetGuardType() == "ACLs" {
				for _, rule := range dt.AclRules {
					if err := domain.Guard.AddRule(rule); err != nil {
						glog.Exit(err)
					}
				}
			}

			if err := domain.Save(); err != nil {
				glog.Exit(err)
			}
		}
	case "policy":
		if *query != "" {
			domain, err := tao.LoadDomain(configPath, nil)
			if err != nil {
				glog.Exit(err)
			}

			fmt.Fprintf(noise, "Querying policy guard with statement: %s\n", *query)
			ok, err := domain.Guard.Query(*query)
			if err != nil {
				glog.Exit(err)
			}
			if ok {
				fmt.Println("The policy implies the statement.")
			} else {
				fmt.Println("The policy does not imply the statement")
			}

			return
		}

		pwd := getKey("policy key password", *pass)
		domain, err := tao.LoadDomain(configPath, pwd)
		if err != nil {
			glog.Exit(err)
		}

		// Clear all the policy stored by the Guard.
		if *clear {
			domain.Guard.Clear()
			if err := domain.Save(); err != nil {
				glog.Exit(err)
			}
		}

		host := dt.GetHostName()
		// Add execution permission for a program.
		if *canExecute != "" {
			path := *canExecute
			prin := makeHostPrin(host)
			subprin, err := makeProgramSubPrin(path)
			if err == nil {
				prog := prin.MakeSubprincipal(subprin)
				fmt.Fprintf(noise, "Authorizing program to execute:\n"+
					"  path: %s\n"+
					"  host: %s\n"+
					"  name: %s\n", path, prin, subprin)
				if err := domain.Guard.Authorize(prog, "Execute", nil); err != nil {
					glog.Exit(err)
				}
				if err = domain.Save(); err != nil {
					glog.Exit(err)
				}
			}
		}
		if *retractCanExecute != "" {
			path := *retractCanExecute
			prin := makeHostPrin(host)
			subprin, err := makeProgramSubPrin(path)
			if err == nil {
				prog := prin.MakeSubprincipal(subprin)
				fmt.Fprintf(noise, "Retracting program authorization to execute:\n"+
					"  path: %s\n"+
					"  host: %s\n"+
					"  name: %s\n", path, prin, subprin)
				if err := domain.Guard.Retract(prog, "Execute", nil); err != nil {
					glog.Exit(err)
				}
			}
		}
		if *add != "" {
			fmt.Fprintf(noise, "Adding policy rule: %s\n", *add)
			if err := domain.Guard.AddRule(*add); err != nil {
				glog.Exit(err)
			}
			if err = domain.Save(); err != nil {
				glog.Exit(err)
			}
		}
		if *retract != "" {
			fmt.Fprintf(noise, "Retracting policy rule: %s\n", *retract)
			if err := domain.Guard.RetractRule(*retract); err != nil {
				glog.Exit(err)
			}
			if err = domain.Save(); err != nil {
				glog.Exit(err)
			}
		}
		if *addPrograms {
			if dt.Config.DomainInfo.GetGuardType() == "Datalog" {
				// Add the hashes of any programs given in the template.
				for _, p := range dt.ProgramPaths {
					prin, err := makeProgramSubPrin(p)
					if err == nil {
						pt := auth.PrinTail{Ext: prin}
						pred := auth.MakePredicate(dt.GetProgramPredicateName(), pt)
						if err := domain.Guard.AddRule(fmt.Sprint(pred)); err != nil {
							glog.Exit(err)
						}
					}
				}
			} else if dt.Config.DomainInfo.GetGuardType() == "ACLs" {
				if host != "" {
					prin := makeHostPrin(host)
					for _, p := range dt.ProgramPaths {
						subprin, err := makeProgramSubPrin(p)
						if err == nil {
							prog := prin.MakeSubprincipal(subprin)
							if err := domain.Guard.Authorize(prog, "Execute", nil); err != nil {
								glog.Exit(err)
							}
						}
					}
					if dt.VmPaths != nil && dt.LinuxHostPaths != nil {
						for _, vm := range dt.VmPaths {
							vmPrin, err := makeVMSubPrin(vm)
							if err == nil {
								for _, lh := range dt.LinuxHostPaths {
									lhPrin, err := makeLinuxHostSubPrin(lh)
									if err == nil {
										var lsp auth.SubPrin
										lsp = append(lsp, vmPrin...)
										lsp = append(lsp, lhPrin...)
										lprog := prin.MakeSubprincipal(lsp)
										if err := domain.Guard.Authorize(lprog, "Execute", nil); err != nil {
											glog.Exit(err)
										}

										for _, p := range dt.ProgramPaths {
											subprin, err := makeProgramSubPrin(p)
											if err == nil {
												var sp auth.SubPrin
												sp = append(sp, vmPrin...)
												sp = append(sp, lhPrin...)
												sp = append(sp, subprin...)
												prog := prin.MakeSubprincipal(sp)
												if err := domain.Guard.Authorize(prog, "Execute", nil); err != nil {
													glog.Exit(err)
												}

												var gsp auth.SubPrin
												gsp = append(gsp, vmPrin...)
												gsp = append(gsp, lhPrin...)
												gsp = append(gsp, domain.Guard.Subprincipal()...)
												gsp = append(gsp, subprin...)
												gprog := prin.MakeSubprincipal(gsp)
												if err := domain.Guard.Authorize(gprog, "Execute", nil); err != nil {
													glog.Exit(err)
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			if err := domain.Save(); err != nil {
				glog.Exit(err)
			}
		}
		if *addContainers {
			if dt.Config.DomainInfo.GetGuardType() == "Datalog" {
				for _, c := range dt.ContainerPaths {
					prin, err := makeContainerSubPrin(c)
					if err == nil {
						pt := auth.PrinTail{Ext: prin}
						pred := auth.MakePredicate(dt.GetContainerPredicateName(), pt)
						if err := domain.Guard.AddRule(fmt.Sprint(pred)); err != nil {
							glog.Exit(err)
						}
					}
				}
			} else if dt.Config.DomainInfo.GetGuardType() == "ACLs" {
				if host != "" {
					prin := makeHostPrin(host)
					for _, p := range dt.ContainerPaths {
						subprin, err := makeContainerSubPrin(p)
						if err == nil {
							prog := prin.MakeSubprincipal(subprin)
							if err := domain.Guard.Authorize(prog, "Execute", nil); err != nil {
								glog.Exit(err)
							}
						}
					}
				}
			}
			if err := domain.Save(); err != nil {
				glog.Exit(err)
			}
		}
		if *addVMs {
			if dt.Config.DomainInfo.GetGuardType() == "Datalog" {
				for _, c := range dt.VmPaths {
					prin, err := makeVMSubPrin(c)
					if err == nil {
						pt := auth.PrinTail{Ext: prin}
						pred := auth.MakePredicate(dt.GetVmPredicateName(), pt)
						if err := domain.Guard.AddRule(fmt.Sprint(pred)); err != nil {
							glog.Exit(err)
						}
					}
				}
			}
			// The ACLs need the full name, so that only happens for containers and programs.
			if err := domain.Save(); err != nil {
				glog.Exit(err)
			}
		}
		if *addLinuxHost {
			if dt.Config.DomainInfo.GetGuardType() == "Datalog" {
				for _, c := range dt.LinuxHostPaths {
					prin, err := makeLinuxHostSubPrin(c)
					if err == nil {
						pt := auth.PrinTail{Ext: prin}
						pred := auth.MakePredicate(dt.GetLinuxHostPredicateName(), pt)
						if err := domain.Guard.AddRule(fmt.Sprint(pred)); err != nil {
							glog.Exit(err)
						}
					}
				}
				// The ACLs need the full name, so that only happens for containers and programs.
				if err := domain.Save(); err != nil {
					glog.Exit(err)
				}
			}
		}
		if *addHost {
			if dt.Config.DomainInfo.GetGuardType() == "Datalog" {
				if host != "" {
					prin := makeHostPrin(host)
					pred := auth.MakePredicate(dt.GetHostPredicateName(), prin)
					if err := domain.Guard.AddRule(fmt.Sprint(pred)); err != nil {
						glog.Exit(err)
					}
				}
				if err := domain.Save(); err != nil {
					glog.Exit(err)
				}
			}
		}
		if *addGuard {
			if dt.Config.DomainInfo.GetGuardType() == "Datalog" {
				subprin := domain.Guard.Subprincipal()
				pt := auth.PrinTail{Ext: subprin}
				pred := auth.Pred{
					Name: dt.GetGuardPredicateName(),
					Arg:  []auth.Term{pt},
				}
				if err := domain.Guard.AddRule(fmt.Sprint(pred)); err != nil {
					glog.Exit(err)
				}
				if err := domain.Save(); err != nil {
					glog.Exit(err)
				}
			}
		}
	case "user":
		upwd := getKey("user password", *userPass)
		pwd := getKey("policy key password", *pass)

		// Read the X509Details for this user from a text protobuf file.
		xdb, err := ioutil.ReadFile(*userKeyDetails)
		if err != nil {
			glog.Exit(err)
		}
		var xd tao.X509Details
		if err := proto.UnmarshalText(string(xdb), &xd); err != nil {
			glog.Exit(err)
		}

		domain, err := tao.LoadDomain(configPath, pwd)
		if err != nil {
			glog.Exit(err)
		}
		policyKey := domain.Keys
		fmt.Fprintf(noise, "Creating key for user: %s\n", xd.GetCommonName())

		subjectName := tao.NewX509Name(&xd)
		_, err = tao.NewSignedOnDiskPBEKeys(tao.Signing, upwd, *userKeyPath, subjectName, int(xd.GetSerialNumber()), policyKey)
		if err != nil {
			glog.Exit(err)
		}
	case "principal":
		args := flag.Args()
		switch *principal {
		case "program":
			if len(args) != 1 {
				glog.Exit("must supply a path to the program")
			}

			path := args[0]
			subprin, err := makeProgramSubPrin(path)
			if err == nil {
				pt := auth.PrinTail{Ext: subprin}
				fmt.Println(pt)
			}
		case "container":
			if len(args) != 1 {
				glog.Exit("must supply a path to the program")
			}

			path := args[0]
			subprin, err := makeContainerSubPrin(path)
			if err == nil {
				pt := auth.PrinTail{Ext: subprin}
				fmt.Println(pt)
			}
		case "tpm":
			f, err := os.OpenFile(*tpmPath, os.O_RDWR, 0600)
			if err != nil {
				glog.Exit(err)
			}
			defer f.Close()

			pcrpe := auth.PrinExt{
				Name: "PCRs",
				Arg:  make([]auth.Term, len(pcrVals)),
			}
			for i, pcr := range pcrVals {
				res, err := tpm.ReadPCR(f, uint32(pcr))
				if err != nil {
					glog.Exit(err)
				}

				pcrpe.Arg[i] = auth.Bytes(res)
			}

			aikblob, err := ioutil.ReadFile(*aikFile)
			if err != nil {
				glog.Exit(err)
			}
			v, err := tpm.UnmarshalRSAPublicKey(aikblob)
			if err != nil {
				glog.Exit(err)
			}
			aik, err := x509.MarshalPKIXPublicKey(v)
			if err != nil {
				glog.Exit(err)
			}

			name := auth.Prin{
				Type: "tpm",
				Key:  auth.Bytes(aik),
				Ext:  []auth.PrinExt{pcrpe},
			}
			fmt.Println(name)
		case "key":
			lhpwd := getKey("key password", *keyPass)
			args := flag.Args()
			if len(args) != 1 {
				glog.Exit("must supply a path for the linux host directory")
			}

			lhpath := path.Join(*domainPath, args[0])
			// Get or create the keys.
			k, err := tao.NewOnDiskPBEKeys(tao.Signing|tao.Crypting|tao.Deriving, lhpwd, lhpath, nil)
			if err != nil {
				glog.Exit(err)
			}

			fmt.Println(k.SigningKey.ToPrincipal())
		default:
			glog.Exitf("Unknown principal type '%s'", *principal)
		}
	default:
		glog.Exitf("Unknown operation '%s'", *operation)
	}
}

func hash(p string) ([]byte, error) {
	// If the path is not absolute, then try $GOPATH/bin/path if it exists.
	realPath := p
	if !path.IsAbs(p) {
		gopath := os.Getenv("GOPATH")
		if gopath != "" {
			realPath = path.Join(path.Join(gopath, "bin"), realPath)
		}
	}
	file, err := os.Open(realPath)
	if err != nil {
		return nil, err
	}
	hasher := sha256.New()
	if _, err = io.Copy(hasher, file); err != nil {
		glog.Exit(err)
	}
	return hasher.Sum(nil), nil
}

func makeHostPrin(host string) auth.Prin {
	if host == "" {
		glog.Exit("the domain template must contain a Tao host in host_name")
	}
	var prin auth.Prin
	if _, err := fmt.Sscanf(host, "%v", &prin); err != nil {
		glog.Exit(err)
	}
	return prin
}

func makeProgramSubPrin(prog string) (auth.SubPrin, error) {
	// TODO(tmroeder): This assumes no IDs, and it assumes linux hosts.
	id := uint(0)
	h, err := hash(prog)
	if err != nil {
		return auth.SubPrin{}, err
	}
	return tao.FormatSubprin(id, h), nil
}

func makeVMSubPrin(prog string) (auth.SubPrin, error) {
	// TODO(tmroeder): This assumes no IDs, and it assumes linux hosts.
	id := uint(0)
	h, err := hash(prog)
	if err != nil {
		return auth.SubPrin{}, err
	}
	return tao.FormatCoreOSSubprin(id, h), nil
}

func makeLinuxHostSubPrin(prog string) (auth.SubPrin, error) {
	// TODO(tmroeder): This assumes no IDs, and it assumes linux hosts.
	id := uint(0)
	h, err := hash(prog)
	if err != nil {
		return auth.SubPrin{}, err
	}
	return tao.FormatLinuxHostSubprin(id, h), nil
}

func makeContainerSubPrin(prog string) (auth.SubPrin, error) {
	// TODO(tmroeder): This assumes no IDs
	id := uint(0)
	h, err := hash(prog)
	if err != nil {
		return auth.SubPrin{}, err
	}
	return tao.FormatDockerSubprin(id, h), nil
}

func getKey(prompt, input string) []byte {
	var pwd []byte
	var err error
	if len(input) == 0 {
		// Get the password from the user.
		fmt.Print(prompt + ": ")
		pwd, err = terminal.ReadPassword(syscall.Stdin)
		if err != nil {
			glog.Exit(err)
		}
		fmt.Println()
	} else {
		glog.Warning("Passwords on the command line are not secure. Use this only for testing")
		pwd = []byte(input)
	}

	return pwd
}
