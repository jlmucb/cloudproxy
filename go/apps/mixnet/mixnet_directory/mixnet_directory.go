// Copyright (c) 2016, Google Inc. All rights reserved.
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
	"crypto/x509/pkix"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/jlmucb/cloudproxy/go/apps/mixnet"
	"github.com/jlmucb/cloudproxy/go/tao"
)

var directoryAddr = flag.String("addr", "127.0.0.1:8123", "Address and port of this directory.")
var network = flag.String("network", "tcp", "Network protocol.")
var configPath = flag.String("config", "tao.config", "Path to domain configuration file.")
var timeoutDuration = flag.String("timeout", "10s", "Timeout on TCP connections, e.g. \"10s\".")

// x509 identity of the mixnet router.
var x509Identity pkix.Name = pkix.Name{
	Organization:       []string{"Google Inc."},
	OrganizationalUnit: []string{"Cloud Security"},
}

func serveRouters(dir *mixnet.DirectoryContext) error {
	for {
		_, err := dir.Accept()
		if err != nil {
			glog.Infoln(err)
			return err
		}
	}
}
func main() {
	flag.Parse()
	timeout, err := time.ParseDuration(*timeoutDuration)
	if err != nil {
		glog.Fatalf("router: failed to parse timeout duration: %s", err)
	}

	dir, err := mixnet.NewDirectoryContext(*configPath, *network, *directoryAddr,
		timeout, &x509Identity, tao.Parent())
	if err != nil {
		glog.Fatalf("failed to configure directory: %s", err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	go func() {
		sig := <-sigs
		glog.Infof("directory: closing on signal: %s", sig)
		dir.Close()
		signo := int(sig.(syscall.Signal))
		os.Exit(0x80 + signo)
	}()

	if err := serveRouters(dir); err != nil {
		glog.Errorf("directory: error while serving: %s", err)
	}

	glog.Flush()
}
