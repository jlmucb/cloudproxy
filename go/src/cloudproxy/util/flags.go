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
	// split {envPrefix}_{envVar}={envVal}
	var envPrefix, envName, envVal []string
	for _, pair := range env {
		p := strings.SplitN(pair, "=", 2)
		k := strings.SplitN(p[0], "_", 2)
		if len(p) == 2 && len(k) == 2 {
			envPrefix = append(envPrefix, k[0])
			envName = append(envName, k[1])
			envVal = append(envVal, p[1])
		}
	}
	// look for each prefix
	for _, prefix := range prefix {
		for i := range envPrefix {
			if envPrefix[i] == prefix {
				if f := flag.Lookup(envName[i]); f != nil {
					f.Value.Set(envVal[i])
				}
			}
		}
	}
}
