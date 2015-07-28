// Copyright (c) 2014, Google, Inc.  All rights reserved.
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
	"path"
	"path/filepath"

	"github.com/golang/glog"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

func main() {
	// child PID is output to fd 3, if it exists, otherwise to stdout
	pidOut := os.Stdout
	if util.IsValidFD(3) {
		pidOut = util.NewFile(3)
	}

	operation := flag.String("operation", "run", "The operation to perform ('run', 'stop', 'kill', 'list', or 'name').")
	sockPath := flag.String("sock", "", "The path to the socket for the linux_host")
	docker := flag.String("docker_img", "", "The path to a tarball to use to create a docker image")
	quiet := flag.Bool("quiet", false, "Be more quiet.")

	flag.Parse()

	var verbose io.Writer
	if *quiet {
		verbose = ioutil.Discard
	} else {
		verbose = os.Stderr
	}

	// If -sock was not given, try $TAO_DOMAIN_CONFIG from env
	if *sockPath == "" {
		configPath := os.Getenv("TAO_DOMAIN_CONFIG")
		if configPath == "" {
			badUsage("Must supply a socket patch for the linux host, or set $TAO_DOMAIN_CONFIG")
		}
		absConfigPath, err := filepath.Abs(configPath)
		fatalIf(err)
		dir := path.Dir(absConfigPath)
		*sockPath = path.Join(dir, "linux_tao_host/admin_socket")
	}

	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{*sockPath, "unix"})
	if err != nil {
		badUsage("Couldn't connect to linux_host: %s", err)
	}
	defer conn.Close()
	client := tao.NewLinuxHostAdminClient(conn)
	switch *operation {
	case "run":
		if flag.NArg() == 0 {
			badUsage("missing program path")
		}
		var subprin auth.SubPrin
		var pid int
		if *docker == "" {
			subprin, pid, err = client.StartHostedProgram(flag.Arg(0), flag.Args()...)
		} else {
			// Drop the first arg for Docker, since it will
			// be handled by the Dockerfile directly.
			// TODO(kwalsh) I don't understand the above comment
			if flag.NArg() == 1 {
				subprin, pid, err = client.StartHostedProgram(*docker)
			} else {
				subprin, pid, err = client.StartHostedProgram(*docker, flag.Args()[1:]...)
			}
		}
		fatalIf(err)
		pidOut.Write([]byte(fmt.Sprintf("%d\n", pid)))
		fmt.Fprintf(verbose, "Started %v\n", subprin)
	case "stop":
		for _, s := range flag.Args() {
			var subprin auth.SubPrin
			if _, err := fmt.Sscanf(s, "%v", &subprin); err != nil {
				badUsage("Not a subprin: %s\n", s)
			}
			if err = client.StopHostedProgram(subprin); err != nil {
				badUsage("Could not stop %s: %s\n", s, err)
			}
		}
	case "kill":
		for _, s := range flag.Args() {
			var subprin auth.SubPrin
			if _, err := fmt.Sscanf(s, "%v", &subprin); err != nil {
				badUsage("Not a subprin: %s\n", s)
			}
			if err = client.KillHostedProgram(subprin); err != nil {
				badUsage("Could not kill %s: %s\n", s, err)
			}
		}
	case "list":
		name, pid, err := client.ListHostedPrograms()
		fatalIf(err)
		for i, p := range pid {
			fmt.Printf("pid=%d %v\n", p, name[i])
		}
		fmt.Printf("%d processes\n", len(pid))
	case "name":
		name, err := client.HostName()
		fatalIf(err)
		fmt.Printf("LinuxHost: %v\n", name)
	default:
		badUsage("Unknown operation '%s'", *operation)
	}

	return
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
