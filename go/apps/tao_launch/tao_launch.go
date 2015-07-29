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
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"

	"github.com/golang/glog"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

func main() {

	operation := flag.String("operation", "run", "The operation to perform ('run', 'stop', 'kill', 'list', or 'name').")
	sockPath := flag.String("sock", "", "The path to the socket for the linux_host")
	docker := flag.String("docker_img", "", "The path to a tarball to use to create a docker image")
	pidfile := flag.String("pidfile", "", "Write hosted program pid to this file")
	namefile := flag.String("namefile", "", "Write hosted program subprin name to this file")
	disown := flag.Bool("disown", false, "Don't wait for hosted program to exit")
	daemon := flag.Bool("daemon", false, "Don't pipe stdio or wait for hosted program to exit")

	flag.Parse()

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
		var pidOut *os.File
		if *pidfile == "-" {
			pidOut = os.Stdout
		} else if *pidfile != "" {
			if pidOut, err = os.Open(*pidfile); err != nil {
				badUsage("Can't open pid file: %s", err)
			}
		}
		var nameOut *os.File
		if *namefile == "-" {
			nameOut = os.Stdout
		} else if *namefile != "" {
			if nameOut, err = os.Open(*namefile); err != nil {
				badUsage("Can't open name file: %s", err)
			}
		}
		var fds [3]int
		var pr, pw [3]*os.File
		if *daemon {
			null, err := os.Open(os.DevNull)
			fatalIf(err)
			fds[0] = int(null.Fd())
			fds[1] = int(null.Fd())
			fds[2] = int(null.Fd())
		} else if *disown {
			fds[0] = int(os.Stdin.Fd())
			fds[1] = int(os.Stdout.Fd())
			fds[2] = int(os.Stderr.Fd())
		} else {
			for i := 0; i < 3; i++ {
				pr[i], pw[i], err = os.Pipe()
				fatalIf(err)
			}
			fds[0] = int(pr[0].Fd())
			fds[1] = int(pw[1].Fd())
			fds[2] = int(pw[2].Fd())
		}
		var subprin auth.SubPrin
		var pid int
		if *docker == "" {
			subprin, pid, err = client.StartHostedProgram(fds[:], flag.Arg(0), flag.Args()...)
		} else {
			// Drop the first arg for Docker, since it will
			// be handled by the Dockerfile directly.
			// TODO(kwalsh) I don't understand the above comment
			if flag.NArg() == 1 {
				subprin, pid, err = client.StartHostedProgram(fds[:], *docker)
			} else {
				subprin, pid, err = client.StartHostedProgram(fds[:], *docker, flag.Args()[1:]...)
			}
		}
		fatalIf(err)
		if pidOut != nil {
			fmt.Fprintln(pidOut, pid)
			pidOut.Close()
		}
		if nameOut != nil {
			fmt.Fprintln(nameOut, subprin)
			nameOut.Close()
		}
		if !*disown && !*daemon {
			// Note: there is a race here, if pids are reused very quickly. That
			// seems unlikely, but there is not much we can do about it anyway.
			child, err := os.FindProcess(pid)
			fatalIf(err)
			status := make(chan int, 1)
			go func() {
				s, err := client.WaitHostedProgram(pid, subprin)
				fatalIf(err)
				status <- s
			}()
			pr[0].Close()
			pw[1].Close()
			pw[2].Close()
			go func() {
				_, err := io.Copy(pw[0], os.Stdin)
				if err != nil {
					glog.Errorf("Error copying stdin: %v", err)
				}
				err = pw[0].Close()
				if err != nil {
					glog.Errorf("Error closing stdin: %v", err)
				}
			}()
			go func() {
				_, err := io.Copy(os.Stdout, pr[1])
				if err != nil {
					glog.Errorf("Error copying stdout: %v", err)
				}
				err = pw[0].Close()
				if err != nil {
					glog.Errorf("Error closing stdout: %v", err)
				}
			}()
			go func() {
				_, err := io.Copy(os.Stderr, pr[1])
				if err != nil {
					glog.Errorf("Error copying stdout: %v", err)
				}
				err = pw[0].Close()
				if err != nil {
					glog.Errorf("Error closing stdout: %v", err)
				}
			}()
			c := make(chan os.Signal, 10) // a little buffering
			signal.Notify(c)
		loop:
			for {
				select {
				case sig := <-c:
					fmt.Printf("signalling child with %v\n", sig)
					err := child.Signal(sig)
					fatalIf(err)
				case s := <-status:
					fmt.Printf("child exiited with status %v\n", s)
					break loop
				}
			}
			signal.Stop(c)
		}
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
