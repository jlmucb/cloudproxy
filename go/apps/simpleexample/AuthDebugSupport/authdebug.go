// Copyright (c) 2014, Google, Inc.,  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// File: authdebug.go

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	//"log"
	//"os"
	//"path"

	//taosupport "github.com/jlmucb/cloudproxy/go/apps/simpleexample/taosupport"
)

var fileName = flag.String("/Domains/xx", "/Domains/xx", "file name")

func main() {
	fmt.Printf("File: %s\n", fileName)
	statement, err := ioutil.ReadFile(*fileName)
	if err != nil {
		fmt.Printf("can't read: %s\n", fileName)
	}
        fmt.Printf("Statement: %x\n", statement);

}
