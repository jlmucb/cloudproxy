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
	ConcreteTypes map[string][]Field
	InterfaceTypes map[string]bool
}

type FieldVisitor struct {
	ConcreteTypes map[string][]Field
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
		if _, ok := tv.ConcreteTypes[name]; !ok {
			tv.ConcreteTypes[name] = make([]Field, 0)
		}

		return &FieldVisitor{
			ConcreteTypes: tv.ConcreteTypes,
			InterfaceTypes: tv.InterfaceTypes,
			Name: name,
		}
	case *ast.ArrayType:
		at := ts.Type.(*ast.ArrayType)
		elt, ok := at.Elt.(*ast.Ident)
		if ok {
			tv.ConcreteTypes[name] = []Field{Field{"elt", ArrayType, elt.Name}}
			fmt.Printf(" is an array of type []%s\n", elt.Name)
		}
	case *ast.Ident:
		id := ts.Type.(*ast.Ident)
		fmt.Printf(" is a %s\n", id.Name)
		tv.ConcreteTypes[name] = []Field{Field{"value", IdentType, id.Name}}
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
	st := fv.ConcreteTypes
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
		ConcreteTypes: fv.ConcreteTypes,
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

type Constant struct {
	Name string
	Value int
}

type ConstantVisitor struct {
	Constants []Constant
}

func (tv *ConstantVisitor) Visit(n ast.Node) ast.Visitor {
	vs, ok := n.(*ast.ValueSpec)
	if !ok {
		return tv
	}

	if len(vs.Names) == 0 {
		return tv
	}

	ident := vs.Names[0]
	if ident.Name == "_" {
		return tv
	}

	if ident.Obj == nil || ident.Obj.Data == nil || ident.Obj.Kind != ast.Con {
		return tv
	}

	value, ok := ident.Obj.Data.(int)
	if !ok {
		return tv
	}

	// Turn the constant name into a C++ constant name.
	name := "k" + strings.Title(ident.Name)

	tv.Constants = append(tv.Constants, Constant{name, value})
	return tv
}

func main() {
	output := os.Stdout

	tset := token.NewFileSet()
	tf, err := parser.ParseFile(tset, "../../tao/auth/binary.go", nil, 0)
	if err != nil {
		fmt.Println(err)
		return
	}

	//ast.Print(tset, tf)

	constantVisitor := &ConstantVisitor{
		Constants: make([]Constant, 0),
	}

	ast.Walk(constantVisitor, tf)

	fmt.Fprintf(output, "The constants are as follows: %v\n", constantVisitor.Constants)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "../../tao/auth/ast.go", nil, 0)
	if err != nil {
		fmt.Println(err)
		return
	}

	tv := &TypeVisitor{
		ConcreteTypes: make(map[string][]Field),
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

	fmt.Fprintln(output, "enum class BinaryTags {")
	for i, constant := range constantVisitor.Constants {
		fmt.Fprintf(output, "  %s = %d", constant.Name, constant.Value)
		if i < len(constantVisitor.Constants) - 1 {
			fmt.Fprint(output, ",")
		}
		fmt.Fprintln(output)
	}
	fmt.Fprintf(output, "};\n\n")

	for name, fields := range tv.ConcreteTypes {
		fmt.Fprintf(output, "class %s", name)
		if _, isForm := formWalker.types[name]; isForm {
			fmt.Fprintf(output, ": public Form")
		} else if _, isTerm := termWalker.types[name]; isTerm {
			fmt.Fprintf(output, ": public Term")
		}

		fmt.Fprintf(output, " {\n")
		fmt.Fprintf(output, " public:\n")

		fmt.Fprintf(output, constructor, name)
		fmt.Fprintln(output)

		fmt.Fprint(output, marshal)
		fmt.Fprintf(output, " override;\n");

		if len(fields) > 0 {
			fmt.Fprintf(output, " private:\n");
		}

		for _, info := range fields {
			typeName := info.TypeName

			if primitives[typeName] {
				if info.Type == StarType {
					typeName = typeName + "*"
				}
				fmt.Fprintf(output, "  %s %s_;\n", typeName, info.Name)
				continue
			}

			switch info.Type {
			case IdentType, StarType:
				fmt.Fprintf(output, "  std::unique_ptr<%s> %s_;\n", info.TypeName, info.Name)
			case ArrayType:
				if info.TypeName == "byte" {
					fmt.Fprintf(output, "  string %s_;\n", info.Name)
					continue
				}

				typeName := info.TypeName
				if tv.InterfaceTypes[typeName] {
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
