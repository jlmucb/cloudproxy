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
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/golang/glog"
)

const stackTraceDepth = 100
const showFileNames = false

var previousTrace []uintptr
var logging sync.Mutex

// Logged prints an error and some context to glog.Error, then returns the same
// error. The intended usage is like so:
//   foo, err := somefunc()
//   if err != nil {
//     return 0, Logged(err)
//   }
//   ...
// The context consists of a stack trace, but omitting parts of the trace that
// were already shown by the most recently printed error.
func Logged(err error) error {
	if err == nil {
		return nil
	}
	// TODO(kwalsh) If glog.Error() will not print, maybe return early?

	stackTrace := make([]uintptr, stackTraceDepth)
	n := runtime.Callers(2, stackTrace)
	stackTrace = stackTrace[:n]

	logging.Lock()
	defer logging.Unlock()

	omit := 0
	p := len(previousTrace)
	for omit < n && omit < p && stackTrace[n-omit-1] == previousTrace[p-omit-1] {
		omit++
	}
	if omit < 2 {
		omit = 0
	}

	var context bytes.Buffer
	for i := 0; i < n-omit; i++ {
		f := runtime.FuncForPC(stackTrace[i])
		file, line := f.FileLine(stackTrace[i])
		if showFileNames {
			parts := strings.SplitAfter(file, "/")
			if len(parts) > 2 {
				file = parts[len(parts)-2] + parts[len(parts)-1]
			}
			fmt.Fprintf(&context, "  [%d] %s:%d %s()\n", i+1, file, line, f.Name())
		} else {
			fmt.Fprintf(&context, "  [%d] line %4d %s()\n", i+1, line, f.Name())
		}
	}
	if omit > 0 {
		// TODO(kwalsh) maybe more info, e.g.:
		// fmt.Fprintf(&context, "  ... %d additional omitted\n", omit)
		fmt.Fprintf(&context, "  ...\n")
	}
	previousTrace = stackTrace

	glog.Error(err.Error() + "; context:\n" + context.String())
	return err
}
