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
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-tpm/tpm"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"golang.org/x/crypto/ssh/terminal"
)

var opts = []options.Option{
	// Flags for all/most commands
	{"tao_domain", "", "<dir>", "Tao domain configuration directory", "all"},
	{"quiet", false, "", "Be more quiet", "all"},
	{"pass", "", "<password>", "Password for policy private key (Testing only!)", "all"},

	// Flags for miscellaneous commands
	{"config_template", "", "<file>", "Configuration template", "init,newsoft,policy"},

	// Flags for 'newsoft', used to create soft tao keys.
	{"soft_pass", "", "<pass>", "A password to encrypt the new soft Tao keys", "newsoft"},

	// Flags for 'init'. If these flags are specified, a public cached version
	// of the domain will also be created.
	{"pub_domain_address", "", "<adddress>", "Address of TaoCA for public cached domain", "init"},
	{"pub_domain_network", "tcp", "<network>", "Network of TaoCA for public cached domain", "init"},
	{"pub_domain_ttl", 30 * time.Second, "<duration>", "Time-to-live of cached policy", "init"},

	// Flags for 'policy' command, used to change and query the policy rules
	// used for principal authorization. The strings passed to these rules
	// depend on the Guard given in the domain/tao.
	{"canexecute", "", "<prog>", "Path of a program to be authorized to execute", "policy"},
	{"retractcanexecute", "", "<prog>", "Path of a program to retract authorization to execute", "policy"},
	{"add", "", "<rule>", "A policy rule to be added", "policy"},
	{"retract", "", "<rule>", "A policy rule to be retracted", "policy"},
	{"query", "", "<rule>", "A policy query to be checked", "policy"},
	{"clear", false, "", "Clear all policy rules before other changes", "policy"},
	{"add_programs", false, "", "Add the program hashes to the policy", "policy"},
	{"add_containers", false, "", "Add the container hashes to the policy", "policy"},
	{"add_host", false, "", "Add the host to the policy", "policy"},
	{"add_vms", false, "", "Add VMs to the policy", "policy"},
	{"add_linux_host", false, "", "Add LinuxHost to the policy", "policy"},
	{"add_guard", false, "", "Add a trusted guard to the policy", "policy"},
	{"add_tpm", false, "", "Add trusted platform module to the policy", "policy"},

	// Flags for 'user' command, used to create new user keys.
	{"user_key_details", "", "<file>", "File containing an X509Details proto", "user"},
	{"user_key_path", "usercreds", "<file>", "Key path", "user"},
	{"user_pass", "", "<pass>", "A password for the new user (Testing only!)", "user"},

	// Flags for the 'principal' option, used to compute principal hashes.
	{"program", "", "<file>", "Path to a program to be hashed", "principal"},
	{"container", "", "<file>", "Path to a container to be hashed", "principal"},
	{"tpm", false, "", "Show the TPM principal name", "principal"},
	{"soft", "", "<dir>", "Path to a linux host directory with a soft Tao key", "principal"},
}

func init() {
	options.Add(opts...)
}

var noise = ioutil.Discard

func help() {
	w := new(tabwriter.Writer)
	w.Init(os.Stderr, 4, 0, 2, ' ', 0)
	av0 := path.Base(os.Args[0])

	fmt.Fprintf(w, "Administrative utility for Tao Domain.\n")
	fmt.Fprintf(w, "Usage:\n")
	fmt.Fprintf(w, "  %s newsoft [options] <dir>\t Create a soft tao key set\n", av0)
	fmt.Fprintf(w, "  %s init [options]\t Initialize a new domain\n", av0)
	fmt.Fprintf(w, "  %s policy [options]\t Manage authorization policies\n", av0)
	fmt.Fprintf(w, "  %s user [options]\t Create user keys\n", av0)
	fmt.Fprintf(w, "  %s principal [options]\t Display principal names/hashes\n", av0)
	fmt.Fprintf(w, "\n")

	categories := []options.Category{
		{"all", "Basic options for most commands"},
		{"newsoft", "Options for 'newsoft' command"},
		{"init", "Options for 'init' command"},
		{"policy", "Options for 'policy' command"},
		{"user", "Options for 'user' command"},
		{"principal", "Options for 'principal' command"},
		{"logging", "Options to control log output"},
	}
	options.ShowRelevant(w, categories...)

	w.Flush()
}

func main() {
	flag.Usage = help

	// Get options before the command verb
	flag.Parse()
	// Get command verb
	cmd := "help"
	if flag.NArg() > 0 {
		cmd = flag.Arg(0)
	}
	// Get options after the command verb
	if flag.NArg() > 1 {
		flag.CommandLine.Parse(flag.Args()[1:])
	}

	if !*options.Bool["quiet"] {
		noise = os.Stdout
	}

	switch cmd {
	case "help":
		help()
	case "newsoft":
		createSoftTaoKeys()
	case "init":
		createDomain()
	case "policy":
		managePolicy()
	case "user":
		createUserKeys()
	case "principal":
		outputPrincipal()
	default:
		options.Usage("Unrecognized command: %s", cmd)
	}
}

// Read the tao_admin domain template for default configuration info.
var savedTemplate *tao.DomainTemplate

func template() *tao.DomainTemplate {
	if savedTemplate == nil {
		configTemplate := *options.String["config_template"]
		if configTemplate == "" {
			options.Usage("Must supply -config_template")
		}
		savedTemplate = new(tao.DomainTemplate)
		pbtext, err := ioutil.ReadFile(configTemplate)
		options.FailIf(err, "Can't read config template")
		err = proto.UnmarshalText(string(pbtext), savedTemplate)
		options.FailIf(err, "Can't parse config template: %s", configTemplate)
	}
	return savedTemplate
}

func domainPath() string {
	if path := *options.String["tao_domain"]; path != "" {
		return path
	}
	if path := os.Getenv("TAO_DOMAIN"); path != "" {
		return path
	}
	options.Usage("Must supply -tao_domain or set $TAO_DOMAIN")
	return ""
}

func configPath() string {
	return path.Join(domainPath(), "tao.config")
}

func managePolicy() {

	// Handle queries first
	if query := *options.String["query"]; query != "" {
		queryGuard(query)
		return
	}

	// Load domain
	pwd := getKey("domain policy key password", "pass")
	domain, err := tao.LoadDomain(configPath(), pwd)
	options.FailIf(err, "Can't load domain")

	// Clear all the policy stored by the Guard.
	if *options.Bool["clear"] {
		domain.Guard.Clear()
		err := domain.Save()
		options.FailIf(err, "Can't save domain")
	}

	// Add permissions
	if canExecute := *options.String["canexecute"]; canExecute != "" {
		host := template().GetHostName()
		addExecute(canExecute, host, domain)
	}
	if add := *options.String["add"]; add != "" {
		fmt.Fprintf(noise, "Adding policy rule: %s\n", add)
		err := domain.Guard.AddRule(add)
		options.FailIf(err, "Can't add rule to domain")
		err = domain.Save()
		options.FailIf(err, "Can't save domain")
	}
	if *options.Bool["add_programs"] {
		host := template().GetHostName()
		addProgramRules(host, domain)
	}
	if *options.Bool["add_containers"] {
		host := template().GetHostName()
		addContainerRules(host, domain)
	}
	if domain.Config.DomainInfo.GetGuardType() == "Datalog" {
		if *options.Bool["add_vms"] {
			addVMRules(domain)
		}
		if *options.Bool["add_linux_host"] {
			addLinuxHostRules(domain)
		}
		if *options.Bool["add_host"] {
			host := template().GetHostName()
			addHostRules(host, domain)
		}
		if *options.Bool["add_guard"] {
			addGuardRules(domain)
		}
		if *options.Bool["add_tpm"] {
			addTPMRules(domain)
		}
	}

	// Retract permissions
	if retract := *options.String["retract"]; retract != "" {
		fmt.Fprintf(noise, "Retracting policy rule: %s\n", retract)
		err := domain.Guard.RetractRule(retract)
		options.FailIf(err, "Can't retract rule from domain")
		err = domain.Save()
		options.FailIf(err, "Can't save domain")
	}
	if retractCanExecute := *options.String["retractcanexecute"]; retractCanExecute != "" {
		host := template().GetHostName()
		retractExecute(retractCanExecute, host, domain)
	}
}

func hash(p string) ([]byte, error) {
	// If the path is not absolute, then try $GOPATH/bin/path if it exists.
	realPath := p
	if !path.IsAbs(p) {
		// TODO(kwalsh) handle case where GOPATH has multiple paths
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
	_, err = io.Copy(hasher, file)
	options.FailIf(err, "Can't hash file")
	return hasher.Sum(nil), nil
}

func makeHostPrin(host string) auth.Prin {
	if host == "" {
		options.Usage("The domain template must contain a Tao host in host_name")
	}
	var prin auth.Prin
	_, err := fmt.Sscanf(host, "%v", &prin)
	options.FailIf(err, "Can't create host principal")
	return prin
}

func makeProgramSubPrin(prog string) (auth.SubPrin, error) {
	// TODO(tmroeder): This assumes no IDs, and it assumes linux hosts.
	id := uint(0)
	h, err := hash(prog)
	if err != nil {
		return auth.SubPrin{}, err
	}
	return tao.FormatProcessSubprin(id, h), nil
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

func makeTPMPrin(tpmPath, aikFile string, pcrNums []int) auth.Prin {
	// Read AIK blob (TPM's public key).
	aikblob, err := ioutil.ReadFile(aikFile)
	options.FailIf(err, "Can't read TPM aik file")

	verifier, err := tpm.UnmarshalRSAPublicKey(aikblob)
	options.FailIf(err, "Can't parse TPM key")

	// Open a connection to the TPM.
	tpmFile, err := os.OpenFile(tpmPath, os.O_RDWR, 0)
	options.FailIf(err, "Can't access TPM")

	// Read registers corresponding to pcrNums.
	pcrVals, err := tao.ReadPCRs(tpmFile, pcrNums)
	tpmFile.Close()
	options.FailIf(err, "Can't read PCRs from TPM")

	// Construct a TPM principal.
	prin, err := tao.MakeTPMPrin(verifier, pcrNums, pcrVals)
	options.FailIf(err, "Can't create TPM principal")

	return prin
}

func getKey(prompt, name string) []byte {
	if input := *options.String[name]; input != "" {
		fmt.Fprintf(os.Stderr, "Warning: Passwords on the command line are not secure. Use -%s option only for testing.\n", name)
		return []byte(input)
	} else {
		// Get the password from the user.
		fmt.Print(prompt + ": ")
		pwd, err := terminal.ReadPassword(syscall.Stdin)
		options.FailIf(err, "Can't get password")
		fmt.Println()
		return pwd
	}
}

func createSoftTaoKeys() {
	dt := template()

	args := flag.Args()
	if len(args) != 1 {
		options.Usage("Must supply a path for the new key set")
	}
	keypath := args[0]

	pwd := getKey("soft tao key password", "soft_pass")

	k, err := tao.NewOnDiskPBEKeys(tao.Signing|tao.Crypting|tao.Deriving, pwd, keypath, tao.NewX509Name(dt.Config.X509Info))
	options.FailIf(err, "Can't create keys")

	fmt.Println(k.VerifyingKey.ToPrincipal())
}

func createDomain() {
	dt := template()
	if dt.Config.DomainInfo.GetPolicyKeysPath() == "" {
		options.Usage("Must supply a policy_keys_path in the domain configuration")
	}

	pwd := getKey("domain policy key password", "pass")

	domain, err := tao.CreateDomain(*dt.Config, configPath(), pwd)
	options.FailIf(err, "Can't create domain")

	if domain.Config.DomainInfo.GetGuardType() == "Datalog" {
		// Add any rules specified in the domain template.
		for _, rule := range dt.DatalogRules {
			err := domain.Guard.AddRule(rule)
			options.FailIf(err, "Can't add rule to domain")
		}
	} else if domain.Config.DomainInfo.GetGuardType() == "ACLs" {
		for _, rule := range dt.AclRules {
			err := domain.Guard.AddRule(rule)
			options.FailIf(err, "Can't add rule to domain")
		}
	}

	err = domain.Save()
	options.FailIf(err, "Can't save domain")

	// Optionally, create a public cached domain.
	if addr := *options.String["pub_domain_address"]; addr != "" {
		net := *options.String["pub_domain_network"]
		ttl := *options.Duration["pub_domain_ttl"]
		_, err = domain.CreatePublicCachedDomain(net, addr, int64(ttl))
		options.FailIf(err, "Can't create public cached domain")
	}
}

func queryGuard(query string) {
	domain, err := tao.LoadDomain(configPath(), nil)
	options.FailIf(err, "Can't load domain")

	ok, err := domain.Guard.Query(query)
	options.FailIf(err, "Can't process query")
	if ok {
		fmt.Println("The policy implies the statement.")
	} else {
		fmt.Println("The policy does not imply the statement")
	}
}

func addExecute(path, host string, domain *tao.Domain) {
	prin := makeHostPrin(host)
	subprin, err := makeProgramSubPrin(path)
	if err == nil {
		prog := prin.MakeSubprincipal(subprin)
		fmt.Fprintf(noise, "Authorizing program to execute:\n"+
			"  path: %s\n"+
			"  host: %s\n"+
			"  name: %s\n", path, prin, subprin)
		err := domain.Guard.Authorize(prog, "Execute", nil)
		options.FailIf(err, "Can't authorize program in domain")
		err = domain.Save()
		options.FailIf(err, "Can't save domain")
	}
}

func retractExecute(path, host string, domain *tao.Domain) {
	prin := makeHostPrin(host)
	subprin, err := makeProgramSubPrin(path)
	if err == nil {
		prog := prin.MakeSubprincipal(subprin)
		fmt.Fprintf(noise, "Retracting program authorization to execute:\n"+
			"  path: %s\n"+
			"  host: %s\n"+
			"  name: %s\n", path, prin, subprin)
		err := domain.Guard.Retract(prog, "Execute", nil)
		options.FailIf(err, "Can't retract program authorization from domain")
	}
}

func addACLPrograms(host string, domain *tao.Domain) {
	if host == "" {
		return
	}
	dt := template()
	prin := makeHostPrin(host)
	for _, p := range dt.ProgramPaths {
		subprin, err := makeProgramSubPrin(p)
		if err != nil {
			continue
		}
		prog := prin.MakeSubprincipal(subprin)
		err = domain.Guard.Authorize(prog, "Execute", nil)
		options.FailIf(err, "Can't authorize program in domain")
	}
	for _, vm := range dt.VmPaths {
		vmPrin, err := makeVMSubPrin(vm)
		if err != nil {
			continue
		}
		for _, lh := range dt.LinuxHostPaths {
			lhPrin, err := makeLinuxHostSubPrin(lh)
			if err != nil {
				continue
			}
			var lsp auth.SubPrin
			lsp = append(lsp, vmPrin...)
			lsp = append(lsp, lhPrin...)
			lprog := prin.MakeSubprincipal(lsp)
			err = domain.Guard.Authorize(lprog, "Execute", nil)
			options.FailIf(err, "Can't authorize program in domain")

			for _, p := range dt.ProgramPaths {
				subprin, err := makeProgramSubPrin(p)
				if err != nil {
					continue
				}
				var sp auth.SubPrin
				sp = append(sp, vmPrin...)
				sp = append(sp, lhPrin...)
				sp = append(sp, subprin...)
				prog := prin.MakeSubprincipal(sp)
				err = domain.Guard.Authorize(prog, "Execute", nil)
				options.FailIf(err, "Can't authorize program in domain")

				var gsp auth.SubPrin
				gsp = append(gsp, vmPrin...)
				gsp = append(gsp, lhPrin...)
				gsp = append(gsp, domain.Guard.Subprincipal()...)
				gsp = append(gsp, subprin...)
				gprog := prin.MakeSubprincipal(gsp)
				err = domain.Guard.Authorize(gprog, "Execute", nil)
				options.FailIf(err, "Can't authorize program in domain")
			}
		}
	}
}

func addProgramRules(host string, domain *tao.Domain) {
	dt := template()
	if domain.Config.DomainInfo.GetGuardType() == "Datalog" {
		// Add the hashes of any programs given in the template.
		for _, p := range dt.ProgramPaths {
			prin, err := makeProgramSubPrin(p)
			if err != nil {
				continue
			}
			pt := auth.PrinTail{Ext: prin}
			pred := auth.MakePredicate(dt.GetProgramPredicateName(), pt)
			err = domain.Guard.AddRule(fmt.Sprint(pred))
			options.FailIf(err, "Can't add rule to domain")
		}
	} else if domain.Config.DomainInfo.GetGuardType() == "ACLs" {
		addACLPrograms(host, domain)
	}
	err := domain.Save()
	options.FailIf(err, "Can't save domain")
}

func addContainerRules(host string, domain *tao.Domain) {
	dt := template()
	if domain.Config.DomainInfo.GetGuardType() == "Datalog" {
		for _, c := range dt.ContainerPaths {
			prin, err := makeContainerSubPrin(c)
			if err != nil {
				continue
			}
			pt := auth.PrinTail{Ext: prin}
			pred := auth.MakePredicate(dt.GetContainerPredicateName(), pt)
			err = domain.Guard.AddRule(fmt.Sprint(pred))
			options.FailIf(err, "Can't add rule to domain")
		}
	} else if domain.Config.DomainInfo.GetGuardType() == "ACLs" && host != "" {
		prin := makeHostPrin(host)
		for _, p := range dt.ContainerPaths {
			subprin, err := makeContainerSubPrin(p)
			if err != nil {
				continue
			}
			prog := prin.MakeSubprincipal(subprin)
			err = domain.Guard.Authorize(prog, "Execute", nil)
			options.FailIf(err, "Can't authorize program in domain")
		}
	}
	err := domain.Save()
	options.FailIf(err, "Can't save domain")
}

func addVMRules(domain *tao.Domain) {
	dt := template()
	for _, c := range dt.VmPaths {
		prin, err := makeVMSubPrin(c)
		if err != nil {
			continue
		}
		pt := auth.PrinTail{Ext: prin}
		pred := auth.MakePredicate(dt.GetVmPredicateName(), pt)
		err = domain.Guard.AddRule(fmt.Sprint(pred))
		options.FailIf(err, "Can't add rule to domain")
	}
	// The ACLs need the full name, so that only happens for containers and
	// programs.
	err := domain.Save()
	options.FailIf(err, "Can't save domain")
}

func addLinuxHostRules(domain *tao.Domain) {
	dt := template()
	for _, c := range dt.LinuxHostPaths {
		prin, err := makeLinuxHostSubPrin(c)
		if err != nil {
			continue
		}
		pt := auth.PrinTail{Ext: prin}
		pred := auth.MakePredicate(dt.GetLinuxHostPredicateName(), pt)
		err = domain.Guard.AddRule(fmt.Sprint(pred))
		options.FailIf(err, "Can't add rule to domain")
	}
	// The ACLs need the full name, so that only happens for containers and
	// programs.
	err := domain.Save()
	options.FailIf(err, "Can't save domain")
}

func addHostRules(host string, domain *tao.Domain) {
	if host == "" {
		return
	}
	dt := template()
	prin := makeHostPrin(host)
	pred := auth.MakePredicate(dt.GetHostPredicateName(), prin)
	err := domain.Guard.AddRule(fmt.Sprint(pred))
	options.FailIf(err, "Can't add rule to domain")
	err = domain.Save()
	options.FailIf(err, "Can't save domain")
}

func addGuardRules(domain *tao.Domain) {
	dt := template()
	subprin := domain.Guard.Subprincipal()
	pt := auth.PrinTail{Ext: subprin}
	pred := auth.Pred{
		Name: dt.GetGuardPredicateName(),
		Arg:  []auth.Term{pt},
	}
	err := domain.Guard.AddRule(fmt.Sprint(pred))
	options.FailIf(err, "Can't add rule to domain")
	err = domain.Save()
	options.FailIf(err, "Can't save domain")
}

func addTPMRules(domain *tao.Domain) {
	dt := template()
	tpmPath, aikFile, pcrNums := getTPMConfig()
	prin := makeTPMPrin(tpmPath, aikFile, pcrNums)

	// TrustedOS predicate from PCR principal tail.
	prinPCRs := auth.PrinTail{Ext: prin.Ext}
	predTrustedOS := auth.MakePredicate(dt.GetOsPredicateName(), prinPCRs)
	err := domain.Guard.AddRule(fmt.Sprint(predTrustedOS))
	options.FailIf(err, "Can't add rule to domain")

	// TrustedTPM predicate from TPM principal.
	prin.Ext = nil
	predTrustedTPM := auth.MakePredicate(dt.GetTpmPredicateName(), prin)
	err = domain.Guard.AddRule(fmt.Sprint(predTrustedTPM))
	options.FailIf(err, "Can't add rule to domain")

	err = domain.Save()
	options.FailIf(err, "Can't save domain")
}

func createUserKeys() {
	// Read the X509Details for this user from a text protobuf file.
	userKeyDetails := *options.String["user_key_details"]
	xdb, err := ioutil.ReadFile(userKeyDetails)
	options.FailIf(err, "Can't read user details")
	var xd tao.X509Details
	err = proto.UnmarshalText(string(xdb), &xd)
	options.FailIf(err, "Can't parse user details: %s", userKeyDetails)

	upwd := getKey("user password", "user_pass")
	pwd := getKey("domain policy key password", "pass")

	domain, err := tao.LoadDomain(configPath(), pwd)
	options.FailIf(err, "Can't load domain")
	policyKey := domain.Keys

	subjectName := tao.NewX509Name(&xd)
	userKeyPath := *options.String["user_key_path"]
	_, err = tao.NewSignedOnDiskPBEKeys(tao.Signing, upwd, userKeyPath, subjectName, int(xd.GetSerialNumber()), policyKey)
	options.FailIf(err, "Can't create user signing key")
}

func getTPMConfig() (string, string, []int) {
	domain, err := tao.LoadDomain(configPath(), nil)
	options.FailIf(err, "Can't load domain")
	tpmPath := domain.Config.GetTpmInfo().GetTpmPath()
	aikFile := domain.Config.GetTpmInfo().GetAikPath()
	pcrVals := domain.Config.GetTpmInfo().GetPcrs()
	var pcrNums []int
	for _, s := range strings.Split(pcrVals, ",") {
		v, err := strconv.ParseInt(s, 10, 32)
		options.FailIf(err, "Can't parse TPM PCR spec")

		pcrNums = append(pcrNums, int(v))
	}

	return tpmPath, aikFile, pcrNums
}

func outputPrincipal() {
	if path := *options.String["program"]; path != "" {
		subprin, err := makeProgramSubPrin(path)
		options.FailIf(err, "Can't create program principal")
		pt := auth.PrinTail{Ext: subprin}
		fmt.Println(pt)
	}
	if path := *options.String["container"]; path != "" {
		subprin, err := makeContainerSubPrin(path)
		options.FailIf(err, "Can't create container principal")
		pt := auth.PrinTail{Ext: subprin}
		fmt.Println(pt)
	}
	if *options.Bool["tpm"] {
		tpmPath, aikFile, pcrVals := getTPMConfig()
		prin := makeTPMPrin(tpmPath, aikFile, pcrVals)
		// In the domain template the host name is in quotes. We need to escape
		// quote strings in the Principal string so that domain_template.pb gets
		// parsed correctly.
		name := strings.Replace(prin.String(), "\"", "\\\"", -1)
		fmt.Println(name)
	}
	if lhpath := *options.String["soft"]; lhpath != "" {
		if !path.IsAbs(lhpath) {
			lhpath = path.Join(domainPath(), lhpath)
		}
		k, err := tao.NewOnDiskPBEKeys(tao.Signing, nil, lhpath, nil)
		options.FailIf(err, "Can't create soft tao keys")
		fmt.Println(k.VerifyingKey.ToPrincipal())
	}
}
