// Binary genauth generates a C++ implementation and serialization from the Go
// version.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

type FieldType int

const (
	IdentType FieldType = iota
	StarType
	ArrayType
)

type Field struct {
	Name string
	Type FieldType
	TypeName string
}

type TypeVisitor struct {
	StructTypes map[string][]Field
	ArrayTypes map[string]string
	IdentTypes map[string]string
	InterfaceTypes map[string]bool
}

type FieldVisitor struct {
	StructTypes map[string][]Field
	ArrayTypes map[string]string
	IdentTypes map[string]string
	InterfaceTypes map[string]bool
	Name string
}

func (tv *TypeVisitor) Visit(n ast.Node) ast.Visitor {
	ts, ok := n.(*ast.TypeSpec)
	if !ok {
		return tv
	}

	name := ts.Name.Name
	fmt.Printf("Type %s", name)
	switch ts.Type.(type) {
	case *ast.StructType:
		fmt.Println(" is a struct")
		if _, ok := tv.StructTypes[name]; !ok {
			tv.StructTypes[name] = make([]Field, 0)
		}

		return &FieldVisitor{
			StructTypes: tv.StructTypes,
			ArrayTypes: tv.ArrayTypes,
			IdentTypes: tv.IdentTypes,
			InterfaceTypes: tv.InterfaceTypes,
			Name: name,
		}
	case *ast.ArrayType:
		at := ts.Type.(*ast.ArrayType)
		elt, ok := at.Elt.(*ast.Ident)
		if ok {
			fmt.Printf(" is an array of type []%s\n", elt.Name)
			tv.ArrayTypes[name] = elt.Name
		}
	case *ast.Ident:
		id := ts.Type.(*ast.Ident)
		fmt.Printf(" is a %s\n", id.Name)
		tv.IdentTypes[name] = id.Name
	case *ast.InterfaceType:
		fmt.Println(" is an interface")
		tv.InterfaceTypes[name] = true
	default:
		fmt.Println(" is not a struct, an array, or an identifier")
	}

	return tv
}

func (fv *FieldVisitor) Visit(n ast.Node) ast.Visitor {
	f, ok := n.(*ast.Field)
	if !ok {
		return fv
	}

	if len(f.Names) == 0 {
		return nil
	}

	name := strings.ToLower(f.Names[0].Name)
	st := fv.StructTypes
	switch f.Type.(type) {
	case *ast.Ident:
		ident := f.Type.(*ast.Ident)
		st[fv.Name] = append(st[fv.Name], Field{name, IdentType, ident.Name})
		fmt.Printf("\t\t%s %s\n", name, ident.Name)
	case *ast.StarExpr:
		star := f.Type.(*ast.StarExpr)
		ident, ok := star.X.(*ast.Ident)
		if ok {
			st[fv.Name] = append(st[fv.Name], Field{name, StarType, ident.Name})
			fmt.Printf("\t\t%s *%s\n", name, ident.Name)
		}
	case *ast.ArrayType:
		atype := f.Type.(*ast.ArrayType)
		elt, ok := atype.Elt.(*ast.Ident)
		if ok {
			st[fv.Name] = append(st[fv.Name], Field{name, ArrayType, elt.Name})
			fmt.Printf("\t\t%s []%s\n", name, elt.Name)
		}
	default:
		fmt.Printf("\t\tField %s is not an identifier or an Array\n", name)
		return fv
	}

	return &TypeVisitor{
		StructTypes: fv.StructTypes,
		IdentTypes: fv.IdentTypes,
		ArrayTypes: fv.ArrayTypes,
		InterfaceTypes: fv.InterfaceTypes,
	}
}

type FuncReceiverWalker struct {
	types map[string]bool
	name string
}

func (fw *FuncReceiverWalker) Visit(n ast.Node) ast.Visitor {
	fd, ok := n.(*ast.FuncDecl)
	if !ok {
		return fw
	}

	if fd.Name.Name != fw.name {
		return fw
	}

	// Record the name of the type of the first receiver.
	if len(fd.Recv.List) == 0 {
		return fw
	}

	field := fd.Recv.List[0]
	ident, ok := field.Type.(*ast.Ident)
	if !ok {
		return fw
	}

	fw.types[ident.Name] = true
	return fw
}

func main() {
	fset := token.NewFileSet()

	f, err := parser.ParseFile(fset, "../../tao/auth/ast.go", nil, 0)
	if err != nil {
		fmt.Println(err)
		return
	}

	tv := &TypeVisitor{
		StructTypes: make(map[string][]Field),
		ArrayTypes: make(map[string]string),
		IdentTypes: make(map[string]string),
		InterfaceTypes: make(map[string]bool),
	}
	ast.Walk(tv, f)

	fmt.Printf("The full set of types is %+v\n", tv)

	formWalker := &FuncReceiverWalker{
		types: make(map[string]bool),
		name: "isForm",
	}
	ast.Walk(formWalker, f)

	fmt.Printf("The following types are Forms: %v\n", formWalker.types)

	termWalker := &FuncReceiverWalker{
		types: make(map[string]bool),
		name: "isTerm",
	}
	ast.Walk(termWalker, f)

	fmt.Printf("The following types are Terms: %v\n", termWalker.types)

	primitives := map[string]bool{
		"string": true,
		"bytes": true,
		"int": true,
		"int64": true,
		"bool": true,
	}

	output := os.Stdout

	includes := `
#include <memory>
#include <vector>

#include <google/protobuf/io/coded_stream.h>
`

	logicElt := `
class LogicElement {
 public:
  virtual bool Marshal(google::protobuf::io::CodedOutputStream* output) = 0;
};`

	form := "class Form : public LogicElement {};\n"
	term := "class Term : public LogicElement {};\n"
	constructor := "  %s(google::protobuf::io::CodedInputStream* input);"
	marshal := "  bool Marshal(google::protobuf::io::CodedOutputStream* output)"


	fmt.Fprintln(output, includes)
	fmt.Fprintln(output, logicElt, "\n")
	fmt.Fprintln(output, form)
	fmt.Fprintln(output, term)

	for k, v := range tv.StructTypes {
		fmt.Fprintf(output, "class %s", k)
		if _, isForm := formWalker.types[k]; isForm {
			fmt.Fprintf(output, ": public Form")
		} else if _, isTerm := termWalker.types[k]; isTerm {
			fmt.Fprintf(output, ": public Term")
		}

		fmt.Fprintf(output, " {\n")
		fmt.Fprintf(output, " public:\n")

		fmt.Fprintf(output, constructor, k)
		fmt.Fprintln(output)

		fmt.Fprint(output, marshal)
		fmt.Fprintf(output, " override;\n");

		if len(v) > 0 {
			fmt.Fprintf(output, " private:\n");
		}

		for _, info := range v {
			typeName := info.TypeName

			if primitives[typeName] {
				if info.Type == StarType {
					typeName = typeName + "*"
				}
				fmt.Fprintf(output, "  %s %s_;\n", typeName, info.Name)
				continue
			}

			isInterface := tv.InterfaceTypes[info.TypeName]
			switch info.Type {
			case IdentType, StarType:
				fmt.Fprintf(output, "  std::unique_ptr<%s> %s_;\n", info.TypeName, info.Name)
			case ArrayType:
				if info.TypeName == "bytes" {
					fmt.Fprintf(output, "  string %s_;\n", info.Name)
					continue
				}

				typeName := info.TypeName
				if isInterface {
					typeName = "std::unique_ptr<" + typeName + ">"
				}
				fmt.Fprintf(output, "  std::vector<%s> %ss_;\n", typeName, info.Name)
			}
		}

		fmt.Fprintf(output, "};\n\n")
	}

	// Generate the class declarations with inheritance that puts the Marshal method on everything. Everything should have a constructor based on the protobuf streams.
	//
	// Then generate the marshalling/demarshalling code.

	// The following line prints the full (immense) AST.
	//ast.Print(fset, f)
}
