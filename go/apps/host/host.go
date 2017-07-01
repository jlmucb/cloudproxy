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

// Package host exposes the functionality of a linux_host implementation as a
// library.
package host

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"syscall"
	"text/tabwriter"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/golang/crypto/ssh/terminal"
	// "golang.org/x/crypto/ssh/terminal"
)

var opts = []options.Option{
	// Flags for all/most commands
	{"tao_domain", "", "<dir>", "Tao domain configuration directory", "all"},
	{"host", "", "<dir>", "Host configuration, relative to domain directory or absolute", "all"},
	{"quiet", false, "", "Be more quiet", "all"},
	{"domain_pass", "", "<password>", "Password for domain policy key", "all"},

	// Flags for init (and start) command
	{"root", false, "", "Create a root host, not backed by any parent Tao", "init,start"},
	{"stacked", false, "", "Create a stacked host, backed by a parent Tao", "init,start"},
	// TODO(kwalsh) hosted program type should be selectable at time of
	// tao_launch. A single host should be able to host all types concurrently.
	{"hosting", "", "<type>", "Hosted program type: process, docker, kvm_coreos or kvm_custom", "init"},
	{"socket_dir", "", "<dir>", "Hosted program socket directory, relative to host directory or absolute", "init"},

	// Flags for start command
	{"foreground", false, "", "Run in the foreground", "start"},
	// Using setsid (1) and shell redirection is an alternative -daemon:
	//    sh$ setsid tao host start ... </dev/null >/dev/null 2>&1
	//    sh$ setsid linux_host start ... </dev/null >/dev/null 2>&1
	{"daemon", false, "", "Detach from tty, close stdio, and run as a daemon", "start"},

	// Flags for root
	{"pass", "", "<password>", "Host password for root hosts (for testing only!)", "root"},

	// Flags for stacked
	{"parent_type", "", "<type>", "Type of channel to parent Tao: TPM, TPM2, pipe, file, or unix", "stacked"},
	{"parent_spec", "", "<spec>", "Spec for channel to parent Tao", "stacked"},

	// Flags for QEMU/KVM CoreOS init
	{"kvm_coreos_img", "", "<path>", "Path to CoreOS.img file, relative to domain or absolute", "kvm"},
	{"kvm_coreos_vm_memory", 0, "SIZE", "The amount of RAM (in KB) to give VM", "kvm"},
	// TODO(kwalsh) shouldn't keys be generated randomly within the host?
	// Otherwise, we need to trust whoever holds the keys, no?
	{"kvm_coreos_ssh_auth_keys", "", "<path>", "An authorized_keys file for SSH to CoreOS guest, relative to domain or absolute", "kvm"},

	// Flags for QEMU/KVM init with custom kernel and initram
	{"kvm_custom_vm_memory", 1024, "SIZE", "The amount of RAM (in KB) to give VM", "kvm_custom"},
}

func init() {
	options.Add(opts...)
}

func help() {
	w := new(tabwriter.Writer)
	w.Init(os.Stderr, 4, 0, 2, ' ', 0)
	av0 := path.Base(os.Args[0])

	fmt.Fprintf(w, "Linux Tao Host\n")
	fmt.Fprintf(w, "Usage:\n")
	fmt.Fprintf(w, "  %s init [options]\t Initialize a new host\n", av0)
	fmt.Fprintf(w, "  %s show [options]\t Show host principal name\n", av0)
	fmt.Fprintf(w, "  %s start [options]\t Start the host\n", av0)
	fmt.Fprintf(w, "  %s stop [options]\t Request the host stop\n", av0)
	fmt.Fprintf(w, "\n")

	categories := []options.Category{
		{"all", "Basic options for most commands"},
		{"init", "Options for 'init' command"},
		{"start", "Options for 'start' command"},
		{"root", "Options for root hosts"},
		{"stacked", "Options for stacked hosts"},
		{"kvm", "Options for hosting QEMU/KVM CoreOS"},
		{"kvm_custom", "Options for hosting QEMU/KVM instance with custom kernel and initram"},
		{"logging", "Options to control log output"},
	}
	options.ShowRelevant(w, categories...)

	w.Flush()
}

var noise = ioutil.Discard

// Main provides the main functionality of linux_host. This is provided as a
// separate function to allow other code to register other Tao implementations
// (with tao.Register) before starting the code.
func Main() {
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
	// Load the domain.
	domain, err := tao.LoadDomain(domainConfigPath(), nil)

	// Set $TAO_DOMAIN so it will be inherited by hosted programs
	os.Unsetenv("TAO_DOMAIN")
	err = os.Setenv("TAO_DOMAIN", domainPath())
	options.FailIf(err, "Can't set $TAO_DOMAIN")

	switch cmd {
	case "help":
		help()
	case "init":
		initHost(domain)
	case "show":
		showHost(domain)
	case "start":
		startHost(domain)
	case "stop", "shutdown":
		stopHost(domain)
	default:
		options.Usage("Unrecognized command: %s", cmd)
	}
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

func domainConfigPath() string {
	return path.Join(domainPath(), "tao.config")
}

func hostPath() string {
	hostPath := *options.String["host"]
	if hostPath == "" {
		// options.Usage("Must supply a -host path")
		hostPath = "linux_tao_host"
	}
	if !path.IsAbs(hostPath) {
		hostPath = path.Join(domainPath(), hostPath)
	}
	return hostPath
}

func hostConfigPath() string {
	return path.Join(hostPath(), "host.config")
}

// Update configuration based on command-line options. Does very little sanity checking.
func configureFromOptions(cfg *tao.LinuxHostConfig) {
	if *options.Bool["root"] && *options.Bool["stacked"] {
		options.Usage("Can supply only one of -root and -stacked")
	} else if *options.Bool["root"] {
		cfg.Type = proto.String("root")
	} else if *options.Bool["stacked"] {
		cfg.Type = proto.String("stacked")
	} else if cfg.Type == nil {
		options.Usage("Must supply one of -root and -stacked")
	}
	if s := *options.String["hosting"]; s != "" {
		cfg.Hosting = proto.String(s)
	}
	if s := *options.String["parent_type"]; s != "" {
		cfg.ParentType = proto.String(s)
	}
	if s := *options.String["parent_spec"]; s != "" {
		cfg.ParentSpec = proto.String(s)
	}
	if s := *options.String["socket_dir"]; s != "" {
		cfg.SocketDir = proto.String(s)
	}
	if s := *options.String["kvm_coreos_img"]; s != "" {
		cfg.KvmCoreosImg = proto.String(s)
	}
	if i := *options.Int["kvm_coreos_vm_memory"]; i != 0 {
		cfg.KvmCoreosVmMemory = proto.Int32(int32(i))
	}
	if s := *options.String["kvm_coreos_ssh_auth_keys"]; s != "" {
		cfg.KvmCoreosSshAuthKeys = proto.String(s)
	}
	if i := *options.Int["kvm_custom_vm_memory"]; i != 0 {
		cfg.KvmCustomVmMemory = proto.Int32(int32(i))
	}
}

func configureFromFile() *tao.LinuxHostConfig {
	d, err := ioutil.ReadFile(hostConfigPath())
	if err != nil {
		options.Fail(err, "Can't read linux host configuration")
	}
	var cfg tao.LinuxHostConfig
	if err := proto.UnmarshalText(string(d), &cfg); err != nil {
		options.Fail(err, "Can't parse linux host configuration")
	}
	return &cfg
}

func loadHost(domain *tao.Domain, cfg *tao.LinuxHostConfig) (*tao.LinuxHost, error) {
	var tc tao.Config

	// Decide host type
	switch cfg.GetType() {
	case "root":
		tc.HostType = tao.Root
	case "stacked":
		tc.HostType = tao.Stacked
	case "":
		options.Usage("Must supply -hosting flag")
	default:
		options.Usage("Invalid host type: %s", cfg.GetType())
	}

	// Decide hosting type
	switch cfg.GetHosting() {
	case "process":
		tc.HostedType = tao.ProcessPipe
	case "docker":
		tc.HostedType = tao.DockerUnix
	case "kvm_coreos":
		tc.HostedType = tao.KVMCoreOSFile
	case "kvm_custom":
		tc.HostedType = tao.KVMCustom
	case "":
		options.Usage("Must supply -hosting flag")
	default:
		options.Usage("Invalid hosting type: %s", cfg.GetHosting())
	}

	// For stacked hosts, figure out the channel type: TPM, TPM2, pipe, file, or unix
	if tc.HostType == tao.Stacked {
		switch cfg.GetParentType() {
		case "TPM":
			tc.HostChannelType = "tpm"
		case "TPM2":
			tc.HostChannelType = "tpm2"
		case "pipe":
			tc.HostChannelType = "pipe"
		case "file":
			tc.HostChannelType = "file"
		case "unix":
			tc.HostChannelType = "unix"
		case "":
			options.Usage("Must supply -parent_type for stacked hosts")
		default:
			options.Usage("Invalid parent type: '%s'", cfg.GetParentType())
		}

		// For stacked hosts on anything but a TPM, we also need parent spec
		if tc.HostChannelType != "tpm" && tc.HostChannelType != "tpm2" {
			tc.HostSpec = cfg.GetParentSpec()
			if tc.HostSpec == "" {
				options.Usage("Must supply -parent_spec for non-TPM stacked hosts")
			}
		} else if tc.HostChannelType == "tpm" {
			// For stacked hosts on a TPM, we also need info from domain config
			if domain.Config.TpmInfo == nil {
				options.Usage("Must provide TPM configuration in the domain to use a TPM")
			}
			tc.TPMAIKPath = path.Join(domainPath(), domain.Config.TpmInfo.GetAikPath())
			tc.TPMPCRs = domain.Config.TpmInfo.GetPcrs()
			tc.TPMDevice = domain.Config.TpmInfo.GetTpmPath()
			tc.TPMAIKCertPath = path.Join(domainPath(), domain.Config.TpmInfo.GetAikCertPath())
		} else if tc.HostChannelType == "tpm2" {
			// For stacked hosts on a TPM2, we also need info from domain config
			if domain.Config.Tpm2Info == nil {
				options.Usage("Must provide TPM2 configuration in the domain to use a TPM2")
			}

			tc.TPM2InfoDir = domainPath()
			tc.TPM2PCRs = domain.Config.Tpm2Info.GetTpm2Pcrs()
			tc.TPM2Device = domain.Config.Tpm2Info.GetTpm2Device()
		}
	}

	rulesPath := ""
	if p := domain.RulesPath(); p != "" {
		rulesPath = path.Join(domainPath(), p)
	}

	// Create the hosted program factory
	socketPath := hostPath()
	if subPath := cfg.GetSocketDir(); subPath != "" {
		if path.IsAbs(subPath) {
			socketPath = subPath
		} else {
			socketPath = path.Join(socketPath, subPath)
		}
	}

	// TODO(cjpatton) How do the NewLinuxDockerContainterFactory and the
	// NewLinuxKVMCoreOSFactory need to be modified to support the new
	// CachedGuard? They probably don't.
	var childFactory tao.HostedProgramFactory
	switch tc.HostedType {
	case tao.ProcessPipe:
		childFactory = tao.NewLinuxProcessFactory("pipe", socketPath)
	case tao.DockerUnix:
		childFactory = tao.NewLinuxDockerContainerFactory(socketPath, rulesPath)
	case tao.KVMCoreOSFile:
		sshFile := cfg.GetKvmCoreosSshAuthKeys()
		if sshFile == "" {
			options.Usage("Must specify -kvm_coreos_ssh_auth_keys for hosting QEMU/KVM CoreOS")
		}
		if !path.IsAbs(sshFile) {
			sshFile = path.Join(domainPath(), sshFile)
		}
		sshKeysCfg, err := tao.CloudConfigFromSSHKeys(sshFile)
		options.FailIf(err, "Can't read ssh keys")

		coreOSImage := cfg.GetKvmCoreosImg()
		if coreOSImage == "" {
			options.Usage("Must specify -kvm_coreos_image for hosting QEMU/KVM CoreOS")
		}
		if !path.IsAbs(coreOSImage) {
			coreOSImage = path.Join(domainPath(), coreOSImage)
		}

		vmMemory := cfg.GetKvmCoreosVmMemory()
		if vmMemory == 0 {
			vmMemory = 1024
		}

		cfg := &tao.CoreOSConfig{
			ImageFile:  coreOSImage,
			Memory:     int(vmMemory),
			RulesPath:  rulesPath,
			SSHKeysCfg: sshKeysCfg,
		}
		childFactory, err = tao.NewLinuxKVMCoreOSFactory(socketPath, cfg)
		options.FailIf(err, "Can't create KVM CoreOS factory")
	case tao.KVMCustom:
		vmMemory := cfg.GetKvmCustomVmMemory()
		if vmMemory == 0 {
			vmMemory = 1024
		}
		cfg := &tao.VmConfig{
			Memory:     int(vmMemory),
			SocketPath: socketPath,
		}
		childFactory = tao.NewLinuxKVMCustomFactory(cfg)
	}

	if tc.HostType == tao.Root {
		pwd := getKey("root host key password", "pass")
		lh, err := tao.NewRootLinuxHost(hostPath(), domain.Guard, pwd, childFactory)
		if err != nil {
			return nil, err
		}
		// Load cert
		rootHost, ok := lh.Host.(*tao.RootHost)
		if !ok {
			return nil, errors.New("Type assertion on newly created root host fails")
		}
		var cert *x509.Certificate
		rawCert, err := ioutil.ReadFile(path.Join(hostPath(), "soft_tao_cert"))
		if err != nil {
			// Create cert signed by policy key
			pwd = getKey("Password for domain policy key", "domain_pass")
			// Load the domain.
			domain, err := tao.LoadDomain(domainConfigPath(), pwd)
			if err != nil {
				return nil, err
			}
			if domain.Keys.SigningKey == nil {
				return nil, errors.New("Domain policy key missing signing key")
			}
			keyName := "Soft Tao Key"
			subject := &pkix.Name{
				Organization: []string{keyName},
				CommonName:   keyName,
			}
			keyType := tao.SignerTypeFromSuiteName(tao.TaoCryptoSuite)
			if keyType == nil {
				return nil, errors.New("Bad key type")
			}
			pkAlg := tao.PublicKeyAlgFromSignerAlg(*keyType)
			sigAlg := tao.SignatureAlgFromSignerAlg(*keyType)
			if pkAlg < 0 || sigAlg < 0 {
				return nil, errors.New("Bad Alg type")
			}
			verifier := rootHost.GetVerifier()
			if verifier == nil {
				return nil, errors.New("Verifier is nil in loadHost")
			}
			cert, err = domain.Keys.SigningKey.CreateSignedX509(domain.Keys.Cert, 1,
				verifier, pkAlg, sigAlg, subject)
			if err != nil {
				return nil, err
			}
			if err = ioutil.WriteFile(path.Join(hostPath(), "soft_tao_cert"),
				cert.Raw, os.ModePerm); err != nil {
				return nil, err
			}
		} else {
			cert, err = x509.ParseCertificate(rawCert)
			if err != nil {
				return nil, err
			}
		}
		rootHost.LoadCert(cert)
		return lh, nil
	} else {
		parent := tao.ParentFromConfig(tc)
		if parent == nil {
			options.Usage("No host tao available, verify -parent_type or $%s\n", tao.HostChannelTypeEnvVar)
		}
		return tao.NewStackedLinuxHost(hostPath(), domain.Guard, tao.ParentFromConfig(tc), childFactory)
	}
}

func initHost(domain *tao.Domain) {
	var cfg tao.LinuxHostConfig

	configureFromOptions(&cfg)
	_, err := loadHost(domain, &cfg)
	options.FailIf(err, "Can't create host")

	// If we get here, keys were created and flags must be ok.

	file, err := util.CreatePath(hostConfigPath(), 0777, 0666)
	options.FailIf(err, "Can't create host configuration")
	cs := proto.MarshalTextString(&cfg)
	fmt.Fprint(file, cs)
	file.Close()
}

func showHost(domain *tao.Domain) {
	cfg := configureFromFile()
	configureFromOptions(cfg)
	host, err := loadHost(domain, cfg)
	options.FailIf(err, "Can't create host")
	fmt.Printf("%v\n", host.HostName())
}

func isBoolFlagSet(name string) bool {
	f := flag.Lookup(name)
	if f == nil {
		return false
	}
	v, ok := f.Value.(flag.Getter).Get().(bool)
	return ok && v
}

func daemonize() {
	// For our purposes, "daemon" means being a session leader.
	sid, _, errno := syscall.Syscall(syscall.SYS_GETSID, 0, 0, 0)
	var err error
	if errno != 0 {
		err = errno
	}
	options.FailIf(err, "Can't get process SID")
	if int(sid) != syscall.Getpid() {
		// Go does not support daemonize(), and we can't simply call setsid
		// because PID may be equal to GID. Using exec.Cmd with the Setsid=true
		// will fork, ensuring that PID differs from GID, then call setsid, then
		// exec ourself again in the new session.
		path, err := os.Readlink("/proc/self/exe")
		options.FailIf(err, "Can't get path to self executable")
		// special case: keep stderr if -logtostderr or -alsologtostderr
		stderr := os.Stderr
		if !isBoolFlagSet("logtostderr") && !isBoolFlagSet("alsologtostderr") {
			stderr = nil
		}
		spa := &syscall.SysProcAttr{
			Setsid: true, // Create session.
		}
		daemon := exec.Cmd{
			Path:        path,
			Args:        os.Args,
			Stderr:      stderr,
			SysProcAttr: spa,
		}
		err = daemon.Start()
		options.FailIf(err, "Can't become daemon")
		fmt.Fprintf(noise, "Linux Tao Host running as daemon\n")
		os.Exit(0)
	} else {
		fmt.Fprintf(noise, "Already a session leader?\n")
	}
}

func startHost(domain *tao.Domain) {

	if *options.Bool["daemon"] && *options.Bool["foreground"] {
		options.Usage("Can supply only one of -daemon and -foreground")
	}
	if *options.Bool["daemon"] {
		daemonize()
	}

	cfg := configureFromFile()
	configureFromOptions(cfg)
	host, err := loadHost(domain, cfg)
	options.FailIf(err, "Can't create host")

	sockPath := path.Join(hostPath(), "admin_socket")
	// Set the socketPath directory go+rx so tao_launch can access sockPath and
	// connect to this linux host, even when tao_launch is run as non-root.
	err = os.Chmod(path.Dir(sockPath), 0755)
	options.FailIf(err, "Can't change permissions")
	uaddr, err := net.ResolveUnixAddr("unix", sockPath)
	options.FailIf(err, "Can't resolve unix socket")
	sock, err := net.ListenUnix("unix", uaddr)
	options.FailIf(err, "Can't create admin socket")
	defer sock.Close()
	err = os.Chmod(sockPath, 0666)
	if err != nil {
		sock.Close()
		options.Fail(err, "Can't change permissions on admin socket")
	}

	go func() {
		fmt.Fprintf(noise, "Linux Tao Service (%s) started and waiting for requests\n", host.HostName())
		err = tao.NewLinuxHostAdminServer(host).Serve(sock)
		fmt.Fprintf(noise, "Linux Tao Service finished\n")
		sock.Close()
		options.FailIf(err, "Error serving admin requests")
		os.Exit(0)
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGTERM)
	<-c
	fmt.Fprintf(noise, "Linux Tao Service shutting down\n")
	err = shutdown()
	if err != nil {
		sock.Close()
		options.Fail(err, "Can't shut down admin socket")
	}

	// The above goroutine will normally end by calling os.Exit(), so we
	// can block here indefinitely. But if we get a second kill signal,
	// let's abort.
	fmt.Fprintf(noise, "Waiting for shutdown....\n")
	<-c
	options.Fail(nil, "Could not shut down linux_host")
}

func stopHost(domain *tao.Domain) {
	err := shutdown()
	if err != nil {
		options.Usage("Couldn't connect to linux_host: %s", err)
	}
}

func shutdown() error {
	sockPath := path.Join(hostPath(), "admin_socket")
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer conn.Close()
	return tao.NewLinuxHostAdminClient(conn).Shutdown()
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
