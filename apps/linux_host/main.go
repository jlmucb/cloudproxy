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
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	"github.com/jlmucb/cloudproxy/util"
)

// General configuration options.
var configPath = flag.String("config_path", "tao.config", "Location of tao domain configuration")
var hostPath = flag.String("path", "linux_tao_host", "Location of linux host configuration")
var rules = flag.String("rules", "rules", "Name of the rules file for auth")
var quiet = flag.Bool("quiet", false, "Be more quiet.")
var root = flag.Bool("root", false, "Run in root mode")
var stacked = flag.Bool("stacked", false, "Run in stacked mode")
var pass = flag.String("pass", "", "Password for unlocking keys if running in root mode")
var channelType = flag.String("channel_type", "pipe", "The type of channel for hosted-program communication ('pipe', or 'unix').")
var channelSocketPath = flag.String("channel_socket_path", "", "The directory in which to create unix sockets for hosted-program communication")
var factoryType = flag.String("factory_type", "process", "The type of hosted program factory to use ('process', 'docker', or 'coreos')")

// Actions to take.
var create = flag.Bool("create", false, "Create a new LinuxHost service.")
var show = flag.Bool("show", false, "Show principal name for LinuxHost service.")
var service = flag.Bool("service", false, "Start the LinuxHost service.")
var shutdown = flag.Bool("shutdown", false, "Shut down the LinuxHost service.")

var run = flag.Bool("run", false, "Start a hosted program (path and args follow --).")
var list = flag.Bool("list", false, "List hosted programs.")
var stop = flag.Bool("stop", false, "Stop a hosted program (names follow --).")
var kill = flag.Bool("kill", false, "Kill a hosted program (names follow --).")
var name = flag.Bool("name", false, "Show the principal name of running LinuxHost.")

// Docker configuration.
var docker = flag.String("docker_img", "", "The path to a tarball to use to create a docker image")

// QEMU/KVM CoreOS configuration with some reasonable defaults.
var coreOSImage = flag.String("coreos_img", "coreos.img", "The path to a CoreOS image")
var sshStartPort = flag.Int("coreos_ssh_port", 2222, "The starting port for SSH connections to CoreOS VMs")
var vmMemory = flag.Int("vm_memory", 1024, "The amount of RAM to give the VM")
var sshFile = flag.String("ssh_auth_keys", "auth_ssh_coreos", "A path to the authorized keys file for SSH connections to the CoreOS guest")
var hostImage = flag.String("host_img", "linux_host.img.tgz", "The path to the Docker image for the Linux host to run under CoreOS")

func countSet(vars ...interface{}) int {
	var n int
	for _, v := range vars {
		switch v := v.(type) {
		case string:
			if v != "" {
				n++
			}
		case bool:
			if v {
				n++
			}
		default:
			n++
		}
	}
	return n
}

var verbose io.Writer

func main() {
	help := "Administrative utility for LinuxHost.\n"
	help += "Usage:\n"
	help += "%[1]s [options] -create\n"
	help += "%[1]s [options] -show\n"
	help += "%[1]s [options] -service\n"
	help += "%[1]s [options] -shutdown\n"
	help += "%[1]s [options] -run -- program args...\n"
	help += "%[1]s [options] -stop -- subprin...\n"
	help += "%[1]s [options] -kill -- subprin...\n"
	help += "%[1]s [options] -list\n"
	help += "%[1]s [options] -name\n"
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, help, os.Args[0])
		flag.PrintDefaults()
	}
	util.UseEnvFlags("GLOG", "TAO", "TAO_HOST")
	flag.Parse()

	if *quiet {
		verbose = ioutil.Discard
	} else {
		verbose = os.Stderr
	}

	if countSet(*create, *show, *service, *shutdown, *run, *stop, *kill, *list, *name) > 1 {
		log.Fatal("specify at most one of the command options")
	}

	sockPath := path.Join(*hostPath, "admin_socket")

	if *create || *service || *show {
		fmt.Fprintf(verbose, "Loading configuration from: %s\n", *configPath)
		domain, err := tao.LoadDomain(*configPath, nil)
		fatalIf(err)

		wd, err := os.Getwd()
		fatalIf(err)
		rulesPath := path.Join(wd, *rules)

		var childFactory tao.HostedProgramFactory
		switch *factoryType {
		case "process":
			childFactory = tao.NewLinuxProcessFactory(*channelType, *channelSocketPath)
		case "docker":
			childFactory = tao.NewLinuxDockerContainerFactory(*channelSocketPath, rulesPath)
		case "coreos":
			if *sshFile == "" {
				log.Fatal("Must specify an SSH authorized_key file for CoreOS")
			}
			sshKeysCfg, err := tao.CloudConfigFromSSHKeys(*sshFile)
			if err != nil {
				log.Fatalf("Couldn't load the ssh files file '%s': %s\n", *sshFile, err)
			}

			if *coreOSImage == "" {
				log.Fatal("Must specify a CoreOS image file for the CoreOS hosted-program factory")
			}

			// Construct the CoreOS configuration from the flags.
			cfg := &tao.CoreOSConfig{
				ImageFile:  *coreOSImage,
				SSHPort:    *sshStartPort,
				Memory:     *vmMemory,
				RulesPath:  rulesPath,
				SSHKeysCfg: sshKeysCfg,
			}
			childFactory = tao.NewLinuxKvmCoreOSContainerFactory(*channelSocketPath, *hostImage, cfg)
		default:
			log.Fatalf("Unknown hosted-program factory '%s'\n", *factoryType)
		}

		var host *tao.LinuxHost
		if *root {
			if len(*pass) == 0 {
				log.Fatal("password is required")
			}
			host, err = tao.NewRootLinuxHost(*hostPath, domain.Guard, []byte(*pass), childFactory)
		} else if *stacked {
			if !tao.Hosted() {
				log.Fatalf("error: no host tao available, check $%s\n", tao.HostTaoEnvVar)
			}
			host, err = tao.NewStackedLinuxHost(*hostPath, domain.Guard, tao.Parent(), childFactory)
		} else {
			log.Fatal("error: must specify either -root or -stacked")
		}
		fatalIf(err)
		if *create {
			fmt.Printf("LinuxHost Service: %s\n", host.TaoHostName())
		} else if *show {
			fmt.Printf("export GOOGLE_TAO_LINUX='%v'\n", host.TaoHostName())
		} else /* service */ {
			sock, err := net.Listen("unix", sockPath)
			fatalIf(err)
			defer sock.Close()
			fmt.Fprintf(verbose, "Linux Tao Service (%s) started and waiting for requests\n", host.TaoHostName())
			fatalIf(err)
			tao.NewLinuxHostAdminServer(host).Serve(sock)
		}
	} else {
		conn, err := net.Dial("unix", sockPath)
		fatalIf(err)
		defer conn.Close()
		client := tao.NewLinuxHostAdminClient(conn)
		if *shutdown {
			log.Fatal("not yet implemented")
		} else if *run {
			if flag.NArg() == 0 {
				log.Fatal("missing program path")
			}
			if *docker == "" {
				subprin, pid, err := client.StartHostedProgram(flag.Arg(0), flag.Args()...)
				fatalIf(err)
				fmt.Printf("%d %v\n", pid, subprin)
			} else {
				// flag.Arg(0) is not necessary here, since it
				// will be pulled off the list by the child
				// factory when it starts the Docker container.
				subprin, pid, err := client.StartHostedProgram(*docker, flag.Args()...)
				fatalIf(err)
				fmt.Printf("%d %v\n", pid, subprin)
			}
		} else if *stop {
			for _, s := range flag.Args() {
				var subprin auth.SubPrin
				_, err := fmt.Sscanf(s, "%v", &subprin)
				fatalIf(err)
				err = client.StopHostedProgram(subprin)
				fatalIf(err)
			}
		} else if *kill {
			for _, s := range flag.Args() {
				var subprin auth.SubPrin
				_, err := fmt.Sscanf(s, "%v", &subprin)
				fatalIf(err)
				err = client.KillHostedProgram(subprin)
				fatalIf(err)
			}
		} else if *list {
			name, pid, err := client.ListHostedPrograms()
			fatalIf(err)
			for i, p := range pid {
				fmt.Printf("pid=%d %v\n", p, name[i])
			}
			fmt.Printf("%d processes\n", len(pid))
		} else if *name {
			name, err := client.TaoHostName()
			fatalIf(err)
			fmt.Printf("LinuxHost: %v\n", name)
		} else {
			name, err := client.TaoHostName()
			fatalIf(err)
			fmt.Printf("LinuxHost: %s\n", name)
		}
	}
}

func fatalIf(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func panicOnHup() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGQUIT)

	s := <-c
	panic(s)
}
