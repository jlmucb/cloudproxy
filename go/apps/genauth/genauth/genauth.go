// Package genauth supports tao auth-code generation from the Go version.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/jlmucb/cloudproxy/go/apps/genauth"
)

var (
	astFile    = flag.String("ast_file", "../../tao/auth/ast.go", "The Go auth AST file to parse")
	binaryFile = flag.String("binary_file", "../../tao/auth/binary.go", "The Go auth binary file to parse")
	headerFile = flag.String("header_file", "auth.h", "The output C++ header to write")
	implFile   = flag.String("impl_file", "auth.cc", "The output C++ implementation to write")
)

func main() {
	flag.Parse()

	headerOutput, err := os.Create(*headerFile)
	if err != nil {
		log.Fatalf("Could not create header file '%s': %v", *headerFile, err)
	}

	implOutput, err := os.Create(*implFile)
	if err != nil {
		log.Fatalf("Could not create implementation file '%s': %v", *implFile, err)
	}

	cg := genauth.ParseAuthAst(*binaryFile, *astFile)

	header := cg.Header()
	for _, line := range header {
		fmt.Fprintln(headerOutput, line)
	}

	impl := cg.Implementation()
	for _, line := range impl {
		fmt.Fprintln(implOutput, line)
	}
}
