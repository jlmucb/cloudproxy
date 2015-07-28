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
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"syscall"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
)

func main() {
	// General configuration options.
	configPath := flag.String("config_path", "", "Location of tao domain configuration")
	trivialPath := flag.String("temp_trivial_domain", "", "Location to create a trival domain configuration")
	hostPath := flag.String("path", "linux_tao_host", "Name of relative path to the location of linux host configuration")
	quiet := flag.Bool("quiet", false, "Be more quiet.")

	// If config_path is given, that is used as the domain config path.
	// Otherwise, if TAO_DOMAIN_CONFIG environment variable is set to a
	// non-empty string, that is used as the domain config path.
	//
	// If temp_trivial_domain is given, then config_path must not be given and
	// TAO_DOMAIN_CONFIG is ignored. In this case, trivial configuration will be
	// created. By default, the trival configuration causes linux_host to run in
	// root mode with a fresh key (so with a soft Tao), and with its
	// configuration stored in a fresh temporary directory, and with a liberal
	// guard policy. Its default method of creating hosted programs is as
	// processes with pipe communication.
	hostType := flag.String("host_type", "auto", "The type of Tao host to implement ('auto', 'root' or 'stacked').")
	pass := flag.String("pass", "BogusPass", "Password for unlocking keys if running in root host mode")
	hostSpec := flag.String("host_spec", "", "The spec to use for communicating with the parent (e.g., '/dev/tpm0')")
	hostChannelType := flag.String("host_channel_type", "", "The type of the host channel (e.g., 'tpm', 'file', or 'unix')")
	hostedProgramType := flag.String("hosted_program_type", "process", "The type of hosted program to create ('process', 'docker', or 'kvm_coreos')")
	hostedProgramSocketPath := flag.String("hosted_program_socket_path", "linux_tao_host", "The directory in which to create unix sockets for hosted-program communication")

	// QEMU/KVM CoreOS configuration with some reasonable defaults.
	coreOSImage := flag.String("kvm_coreos_img", "coreos.img", "The path to a CoreOS image")
	vmMemory := flag.Int("kvm_coreos_vm_memory", 1024, "The amount of RAM to give the VM")
	sshFile := flag.String("kvm_coreos_ssh_auth_keys", "auth_ssh_coreos", "A path to the authorized keys file for SSH connections to the CoreOS guest")

	// An action for the service to take.
	action := flag.String("action", "start", "The action to take ('init', 'show', 'start', or 'stop')")
	flag.Parse()

	var verbose io.Writer
	if *quiet {
		verbose = ioutil.Discard
	} else {
		verbose = os.Stderr
	}

	// If temp_trivial_domain was given, create a temp domain.
	if *trivialPath != "" {
		if *configPath != "" {
			badUsage("Conflicting options given: config_path, init_trivial_domain")
		}
		if err := os.MkdirAll(*trivialPath, 0777); err != nil {
			badUsage("Couldn't create directory for trivial domain %s: %s", *trivialPath, err)
		}
		// We need a password to create a set of temporary policy keys.
		if len(*pass) == 0 {
			badUsage("Must provide a password for temporary keys")
		}
		if *hostType == "auto" {
			*hostType = "root"
		}

		*configPath = path.Join(*trivialPath, "tao.config")
		absConfigPath, err := filepath.Abs(*configPath)
		fatalIf(err)
		cfg := tao.DomainConfig{
			DomainInfo: &tao.DomainDetails{
				Name:           proto.String("testing"),
				PolicyKeysPath: proto.String("policy_keys"),
				GuardType:      proto.String("AllowAll"),
			},
			X509Info: &tao.X509Details{
				CommonName:   proto.String("testing"),
				Country:      proto.String("US"),
				State:        proto.String("WA"),
				Organization: proto.String("CloudProxy"),
			},
		}
		trivialConfig := proto.MarshalTextString(&cfg)
		err = ioutil.WriteFile(absConfigPath, []byte(trivialConfig), 0644)
		fatalIf(err)
		_, err = tao.CreateDomain(cfg, absConfigPath, []byte(*pass))
		fatalIf(err)
	} else if *configPath == "" {
		*configPath = os.Getenv("TAO_DOMAIN_CONFIG")
		if *configPath == "" {
			badUsage("No tao domain configuration specified. Use -config_path or set $TAO_DOMAIN_CONFIG")
		}
	}

	absConfigPath, err := filepath.Abs(*configPath)
	fatalIf(err)
	dir := path.Dir(absConfigPath)
	absHostPath := path.Join(dir, *hostPath)
	sockPath := path.Join(absHostPath, "admin_socket")

	// Load the domain.
	domain, err := tao.LoadDomain(absConfigPath, nil)
	fatalIf(err)
	glog.Info("Domain guard: ", domain.Guard)

	switch *hostType {
	case "auto":
		aikpath := path.Join(dir, domain.Config.TpmInfo.GetAikPath())
		if _, err = os.Stat(aikpath); err == nil {
			*hostType = "TPM"
		} else {
			*hostType = "root"
		}
	case "root":
	case "TPM":
	default:
		badUsage("Invalid argument for -host_type option")
	}

	tc := tao.Config{
		HostType:        tao.HostTaoTypeMap[*hostType],
		HostChannelType: tao.HostTaoChannelMap[*hostChannelType],
		HostSpec:        *hostSpec,
		HostedType:      tao.HostedProgramTypeMap[*hostedProgramType],
	}

	if tc.HostChannelType == tao.TPM {
		// Look up the TPM information in the domain config.
		if domain.Config.TpmInfo == nil {
			glog.Infof("must provide TPM configuration info in the domain to use a TPM")
			return
		}

		tc.TPMAIKPath = path.Join(dir, domain.Config.TpmInfo.GetAikPath())
		tc.TPMPCRs = domain.Config.TpmInfo.GetPcrs()
		tc.TPMDevice = domain.Config.TpmInfo.GetTpmPath()
	}

	absChannelSocketPath := path.Join(dir, *hostedProgramSocketPath)

	// Get the Tao parent from the config information if possible.
	if tc.HostType == tao.Stacked {
		if tao.ParentFromConfig(tc) == nil {
			badUsage("error: no host tao available, check $%s or set --host_channel_type\n", tao.HostChannelTypeEnvVar)
		}
	}

	switch *action {
	case "init", "show", "start":
		rules := domain.RulesPath()
		var rulesPath string
		if rules != "" {
			rulesPath = path.Join(dir, rules)
		}

		// TODO(cjpatton) How do the NewLinuxDockerContainterFactory and the
		// NewLinuxKVMCoreOSFactory need to be modified to support the new
		// CachedGuard? They probably don't.
		var childFactory tao.HostedProgramFactory
		switch tc.HostedType {
		case tao.ProcessPipe:
			childFactory = tao.NewLinuxProcessFactory("pipe", absChannelSocketPath)
		case tao.DockerUnix:
			childFactory = tao.NewLinuxDockerContainerFactory(absChannelSocketPath, rulesPath)
		case tao.KVMCoreOSFile:
			if *sshFile == "" {
				badUsage("Must specify an SSH authorized_key file for CoreOS")
			}
			sshKeysCfg, err := tao.CloudConfigFromSSHKeys(*sshFile)
			if err != nil {
				badUsage("Couldn't load the ssh files file '%s': %s", *sshFile, err)
			}

			if *coreOSImage == "" {
				badUsage("Must specify a CoreOS image file for the CoreOS hosted-program factory")
			}

			// Construct the CoreOS configuration from the flags.
			cfg := &tao.CoreOSConfig{
				ImageFile:  *coreOSImage,
				Memory:     *vmMemory,
				RulesPath:  rulesPath,
				SSHKeysCfg: sshKeysCfg,
			}
			childFactory, err = tao.NewLinuxKVMCoreOSFactory(absChannelSocketPath, cfg)
			fatalIf(err)
		default:
			badUsage("Unknown hosted-program factory '%d'", tc.HostedType)
		}

		var host *tao.LinuxHost
		switch tc.HostType {
		case tao.Root:
			if len(*pass) == 0 {
				badUsage("password is required")
			}
			host, err = tao.NewRootLinuxHost(absHostPath, domain.Guard, []byte(*pass), childFactory)
			fatalIf(err)
		case tao.Stacked:

			if tao.ParentFromConfig(tc) == nil {
				badUsage("error: no host tao available, check $%s or set --host_channel_type", tao.HostChannelTypeEnvVar)
			}
			host, err = tao.NewStackedLinuxHost(absHostPath, domain.Guard, tao.ParentFromConfig(tc), childFactory)
			fatalIf(err)
		default:
			badUsage("error: must specify either --host_type as either 'root' or 'stacked'")
		}

		switch *action {
		case "show":
			fmt.Printf("%v", host.HostName())
		case "start":
			// Make sure callers can read the directory that
			// contains the socket.
			err := os.Chmod(path.Dir(sockPath), 0755)
			fatalIf(err)

			// The Serve method on the linux host admin server
			// requires a UnixListener, since it uses this listener
			// to get the UID and GID of callers. So, we have to use
			// the Unix-based net functions rather than the generic
			// ones.
			uaddr, err := net.ResolveUnixAddr("unix", sockPath)
			fatalIf(err)
			sock, err := net.ListenUnix("unix", uaddr)
			fatalIf(err)
			defer sock.Close()
			err = os.Chmod(sockPath, 0666)
			if err != nil {
				sock.Close()
				glog.Fatal(err)
			}

			go func() {
				c := make(chan os.Signal, 1)
				signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGTERM)
				fmt.Fprintf(verbose, "Linux Tao Service (%s) started and waiting for requests\n", host.HostName())
				err = tao.NewLinuxHostAdminServer(host).Serve(sock)
				fmt.Fprintf(verbose, "Linux Tao Service finished\n")
				sock.Close()
				fatalIf(err)
				os.Exit(0)
			}()

			c := make(chan os.Signal, 1)
			signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGTERM)
			<-c
			fmt.Fprintf(verbose, "Linux Tao Service shutting down\n")
			err = shutdown(sockPath)
			fatalIf(err)

			// The above goroutine will normally end by calling os.Exit(), so we
			// can block here indefinitely. But if we get a second kill signal,
			// let's abort.
			fmt.Fprintf(verbose, "Waiting for shutdown....\n")
			<-c
			glog.Fatalf("Could not shut down linux_host")

		}
	case "shutdown":
	case "stop":
		err = shutdown(sockPath)
		if err != nil {
			badUsage("Couldn't connect to linux_host: %s", err)
		}
	default:
		badUsage("unrecognized command: %s", *action)
	}

	glog.Flush()
}

func shutdown(sockPath string) error {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return err
	}
	defer conn.Close()
	uconn, ok := conn.(*net.UnixConn)
	if !ok {
		glog.Fatalf("Connection not a unix domain socket")
	}
	return tao.NewLinuxHostAdminClient(uconn).Shutdown()
}

func fatalIf(err error) {
	if err != nil {
		glog.FatalDepth(1, err)
	}
}

func badUsage(msg string, args ...interface{}) {
	if msg[len(msg)-1] != '\n' {
		msg += "\n"
	}
	fmt.Fprintf(os.Stderr, msg, args...)
	os.Exit(1)
}
