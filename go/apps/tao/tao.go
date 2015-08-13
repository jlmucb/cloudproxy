// Copyright (c) 2015, Kevin Walsh.  All rights reserved.
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
	"os"
	"strings"
	"syscall"

	_ "github.com/golang/glog"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/util/options"
)

// This file does not use package glog or package flag. It is intended to be a
// thin wrapper around the other commands, and it deliberately does not parse
// most arguments.

func help() {
	help := "Usage: %[1]s [-help] <command> <args>\n"
	help += "\n"
	help += "Options:\n"
	help += "  -help                 Show this help message\n"
	help += "  -help <command>       Show help on <command>\n"
	help += "\n"
	help += "Commands:\n"
	help += "   domain         Configure and manage Tao domains\n"
	help += "   host           Start and stop a Tao host\n"
	help += "   run            Start a new hosted program\n"
	help += "   list           List hosted programs\n"
	help += "   stop           Stop hosted programs\n"
	help += "   kill           Kill hosted programs\n"
	help += "\n"

	fmt.Fprintf(os.Stderr, help, os.Args[0])
	logging := options.Category{"logging", "Options to control log output"}
	options.ShowRelevant(os.Stderr, logging)
}

func match(s string, a ...string) bool {
	for _, v := range a {
		if s == v {
			return true
		}
	}
	return false
}

func flagName(arg string) string {
	if arg == "" || arg[0] != '-' {
		return ""
	}
	arg = arg[1:]
	if len(arg) > 0 && arg[0] == '-' {
		arg = arg[1:]
	}
	return arg
}

func main() {
	// tao -help ==> show main help
	// tao ==> show main help
	// tao [commonopts] cmd [otheropts] ==> some_cmd [commonopts] [otheropts]

	boolopts := []string{"quiet", "help"}
	valopts := []string{"tao_domain"}

	flag.VisitAll(func(f *flag.Flag) {
		type BoolFlag interface {
			IsBoolFlag() bool
		}
		if b, ok := f.Value.(BoolFlag); ok && b.IsBoolFlag() {
			boolopts = append(boolopts, f.Name)
		} else {
			valopts = append(valopts, f.Name)
		}
	})

	var args []string
	cmd := "help"
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "help" || arg == "-?" {
			args = append(args, "-help")
			continue
		}
		if arg == "--" {
			args = append(args, os.Args[i:]...)
			break
		}
		if arg == "" || arg[0] != '-' {
			cmd = arg
			args = append(args, os.Args[i+1:]...)
			break
		}
		if e := strings.Index(arg, "="); e != -1 { // -name=val
			name := flagName(arg[0:e])
			if !match(name, boolopts...) && !match(name, valopts...) {
				options.Usage("Unrecognized option: %s", arg)
			}
			args = append(args, arg)
		} else if match(flagName(arg), boolopts...) { // -bool
			args = append(args, arg)
		} else if match(flagName(arg), valopts...) { // -name val
			if i+1 >= len(os.Args) {
				options.Usage("flag needs an argument: %s", arg)
			}
			args = append(args, arg, os.Args[i+1])
			i++
		} else {
			options.Usage("Unrecognized option: %s", arg)
		}
	}

	// Add a default --tao_domain
	// config := os.Getenv("TAO_DOMAIN")
	// if config != "" {
	// 	arg := fmt.Sprintf("--tao_domain='%s'", config)
	// 	args = append([]string{arg}, args...)
	// }

	// Add a default --log_dir
	logdir := os.TempDir() + "/tao_log"
	if !util.IsDir(logdir) {
		err := os.Mkdir(logdir, 0777)
		options.FailIf(err, "Can't create log directory: %s", logdir)
		err = os.Chmod(logdir, 0777)
		options.FailIf(err, "Can't set permissions on log directory: %s", logdir)
	}
	arg := fmt.Sprintf("--log_dir=%s", logdir)
	args = append([]string{arg}, args...)

	// Maybe add --alsologtostderr=true too?

	switch cmd {
	case "help":
		help()
	case "domain":
		subcmd(cmd, "tao_admin", args)
	case "host":
		subcmd(cmd, "linux_host", args)
	case "run", "list", "stop", "kill":
		subcmd(cmd, "tao_launch", args)
	default:
		options.Usage("Unrecognized tao command: %s", cmd)
	}
}

func subcmd(cmd, prog string, args []string) {
	dirs := util.LiberalSearchPath()
	binary := util.FindExecutable(prog, dirs)
	if binary == "" {
		options.Fail(nil, "Can't find `%s` on path '%s'", prog, strings.Join(dirs, ":"))
	}
	args = append([]string{"tao_" + cmd}, args...)
	err := syscall.Exec(binary, args, os.Environ())
	options.Fail(err, "Can't exec `%s`", cmd)
}
