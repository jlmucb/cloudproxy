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

package util

import (
	"flag"
	"os"
	"strings"
)

// UseEnvFlags pulls variables from the environment to use as values for flags.
// For each prefix X, an environment variable X_f will be used as the value for
// flag f. If flag.Parse() has not been called, then flags on the command line
// will override those from the environment. Otherwise environment flags will
// override those on the command line.
func UseEnvFlags(prefix ...string) {
	env := os.Environ()
	// split {envName}={envVal}
	var envName, envVal []string
	for _, pair := range env {
		p := strings.SplitN(pair, "=", 2)
		if len(p) == 2 {
			envName = append(envName, p[0])
			envVal = append(envVal, p[1])
		}
	}
	// look for each prefix
	for _, prefix := range prefix {
		n := len(prefix) + 1
		for i := range envName {
			if strings.HasPrefix(envName[i], prefix+"_") {
				if f := flag.Lookup(envName[i][n:]); f != nil {
					f.Value.Set(envVal[i])
				}
			}
		}
	}
}
