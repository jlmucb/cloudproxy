// Binary genauth generates a C++ implementation and serialization from the Go
// version.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"strings"
)

var primitives = map[string]bool{
	"bool": true,
	"int": true,
	"int64": true,
	"string": true,
}

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
	switch ts.Type.(type) {
	case *ast.StructType:
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
		}
	case *ast.Ident:
		id := ts.Type.(*ast.Ident)
		tv.ConcreteTypes[name] = []Field{Field{"value", IdentType, id.Name}}
	case *ast.InterfaceType:
		tv.InterfaceTypes[name] = true
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
	case *ast.StarExpr:
		star := f.Type.(*ast.StarExpr)
		ident, ok := star.X.(*ast.Ident)
		if ok {
			st[fv.Name] = append(st[fv.Name], Field{name, StarType, ident.Name})
		}
	case *ast.ArrayType:
		atype := f.Type.(*ast.ArrayType)
		elt, ok := atype.Elt.(*ast.Ident)
		if ok {
			st[fv.Name] = append(st[fv.Name], Field{name, ArrayType, elt.Name})
		}
	default:
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

const headerPrefix = `#include <memory>
#include <string>
#include <vector>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/stubs/common.h>

namespace tao {

class LogicElement {
 public:
  virtual void Marshal(google::protobuf::io::CodedOutputStream* output) = 0;
  virtual bool Unmarshal(google::protobuf::io::CodedInputStream* input) = 0;
};

class Form: public LogicElement {
 public:
  virtual ~Form() = default;
  virtual void Marshal(google::protobuf::io::CodedOutputStream* output) = 0;
  virtual bool Unmarshal(google::protobuf::io::CodedInputStream* input) = 0;
};

class Term: public LogicElement {
 public:
  virtual ~Term() = default;
  virtual void Marshal(google::protobuf::io::CodedOutputStream* output) = 0;
  virtual bool Unmarshal(google::protobuf::io::CodedInputStream* input) = 0;
};
`

func writeHeader(constants []Constant, types map[string][]Field, interfaces map[string]bool, formTypes map[string]bool, termTypes map[string]bool) []string {
	header := strings.Split(headerPrefix, "\n")

	constructor := "  %s() = default;"
	marshal := "  void Marshal(google::protobuf::io::CodedOutputStream* output)"
	unmarshal := "  bool Unmarshal(google::protobuf::io::CodedInputStream* input)"

	header = append(header, "enum class BinaryTags {")
	for i, constant := range constants {
		value := fmt.Sprintf("  %s = %d", constant.Name, constant.Value)
		if i < len(constants) - 1 {
			value += ","
		}
		header = append(header, value)
	}
	header = append(header, "};", "")

	for name, _ := range types {
		header = append(header, "class " + name + ";")
	}
	header = append(header, "")

	for name, fields := range types {
		class := fmt.Sprintf("class %s", name)
		isSubclass := false
		if _, isForm := formTypes[name]; isForm {
			class += ": public Form"
			isSubclass = true
		} else if _, isTerm := termTypes[name]; isTerm {
			class += ": public Term"
			isSubclass = true
		}

		class += " {"
		header = append(header, class, " public:")

		header = append(header, fmt.Sprintf(constructor, name))
		var override string
		if isSubclass {
			override = " override"
		}
		header = append(header, fmt.Sprintf("  ~%s()%s = default;", name, override))
		header = append(header, fmt.Sprintf("%s%s;", marshal, override))
		header = append(header, fmt.Sprintf("%s%s;", unmarshal, override))

		for _, info := range fields {
			typeName := info.TypeName

			if primitives[typeName] {
				if info.Type == StarType {
					typeName = typeName + "*"
					// It shouldn't be possible for this to collide with names from the types, since those are Go names, which shouldn't have underscores in them.
					header = append(header, fmt.Sprintf("  bool %s_present_;", info.Name))
				}

				if typeName == "string" {
					typeName = "std::string"
				}

				if typeName == "int64*" {
					// This is not a pointer in the C++ version. The type switch is needed to get the CodedInputStream unmarshalling to work.
					typeName = "google::protobuf::uint64"
				}

				if typeName == "int" {
					// The type switch is needed to get the CodedInputStream unmarshalling to work.
					typeName = "google::protobuf::uint32"
				}

				header = append(header, fmt.Sprintf("  %s %s_;", typeName, info.Name))
				continue
			}

			switch info.Type {
			case IdentType, StarType:
				header = append(header, fmt.Sprintf("  std::unique_ptr<%s> %s_;", info.TypeName, info.Name))
			case ArrayType:
				if info.TypeName == "byte" {
					header = append(header, fmt.Sprintf("  std::string %s_;", info.Name))
					continue
				}

				typeName = "std::unique_ptr<" + info.TypeName + ">"
				header = append(header, fmt.Sprintf("  std::vector<%s> %ss_;", typeName, info.Name))
			}
		}

		header = append(header, "};", "")
	}

	return append(header, "}  // namespace tao")
}

// The following constants are raw implementation strings that don't need any
// parametrization.
const (
	implHeader = `#include "auth.h"
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>

namespace tao {
namespace {
// This is the canonical implementation of make_unique for C++11. It is wrapped
// in an anonymous namespace to keep it from conflicting with the real thing if
// it exists.
template<typename T, typename ...Args>
std::unique_ptr<T> make_unique( Args&& ...args )
{
    return std::unique_ptr<T>( new T( std::forward<Args>(args)... ) );
}
}  // namespace

using google::protobuf::uint64;
using google::protobuf::uint32;
using google::protobuf::io::ArrayInputStream;
using google::protobuf::io::CodedInputStream;
using google::protobuf::io::CodedOutputStream;
using std::string;

namespace {
`

	encodeString = `void EncodeString(const string& str, CodedOutputStream* output) {
  output->WriteVarint32(str.size());
  output->WriteString(str);
}

`

	decodeString = `bool DecodeString(CodedInputStream* input, string* str) {
  uint32 size = 0;
  if (!input->ReadVarint32(&size)) return false;
  return input->ReadString(str, size);
}

`

	peekTag = `bool PeekTag(CodedInputStream* input, uint32* tag) {
  const void* ptr = nullptr;
  int size = 0;
  if (!input->GetDirectBufferPointer(&ptr, &size)) return false;

  ArrayInputStream array_stream(ptr, size);
  CodedInputStream temp_input(&array_stream);
  return temp_input.ReadVarint32(tag);
}

`

	unmarshalTemplate = "bool %s::Unmarshal(CodedInputStream* input) {"
	marshalTemplate = "void %s::Marshal(CodedOutputStream* output) {"
)

func writeDecoder(constants []Constant, interfaceName string, types map[string]bool) []string {
	impl := []string{
		"bool Decode" + interfaceName + "(uint32 tag, CodedInputStream* input, std::unique_ptr<" + interfaceName + ">* value) {",
		"  switch(tag) {",
	}
	for _, constant := range constants {
		typeName := strings.TrimPrefix(constant.Name, "kTag")
		if _, ok := types[typeName]; !ok {
			continue
		}

		impl = append(impl, []string{
			"  case static_cast<uint32>(BinaryTags::" + constant.Name + "):",
			"    *value = make_unique<" + typeName + ">();",
			"    break;",
		}...)
	}

	impl = append(impl, "  default:", "    return false;")
	impl = append(impl, "  }", "  return (*value)->Unmarshal(input);", "}", "")
	return impl
}

func writeUnmarshaller(name string, fields []Field, interfaces map[string]bool, forms map[string]bool, terms map[string]bool) []string {
	impl := []string{fmt.Sprintf(unmarshalTemplate, name)}
	tag := "BinaryTags::kTag" + name
	impl = append(impl, []string{
		"  uint32 type_tag = 0;",
		"  if (!input->ReadVarint32(&type_tag)) return false;",
		fmt.Sprintf("  if (type_tag != static_cast<uint32>(%s)) return false;", tag),
	}...)
	for _, field := range fields {
		typeName := field.TypeName

		if typeName == "string" {
			impl = append(impl, fmt.Sprintf("  if (!DecodeString(input, &%s_)) return false;", field.Name))
			continue
		}

		if typeName == "int" {
			impl = append(impl, fmt.Sprintf("  if (!input->ReadVarint32(&%s_)) return false;", field.Name))
			continue
		}

		if typeName == "bool" {
			impl = append(impl, []string{
				fmt.Sprintf("  uint32 %s_value = 0;", field.Name),
				fmt.Sprintf("  if (!input->ReadVarint32(&%s_value)) return false;", field.Name),
				fmt.Sprintf("  %s_ = !!%s_value;", field.Name, field.Name),
			}...)
			continue
		}

		if typeName == "int64" && field.Type == StarType {
			// This has a boolean value that says whether or
			// not to expect an int64 field next.
			impl = append(impl, []string{
				fmt.Sprintf("  uint32 %s_present_value = 0;", field.Name),
				fmt.Sprintf("  if (!input->ReadVarint32(&%s_present_value)) return false;", field.Name),
				fmt.Sprintf("  %s_present_ = !!%s_present_value;", field.Name, field.Name),
				fmt.Sprintf("  if (%s_present_) {", field.Name),
				fmt.Sprintf("    if (!input->ReadVarint64(&%s_)) return false;", field.Name),
				"  }",
			}...)
			continue
		}

		switch field.Type {
		case IdentType:
			if interfaces[typeName] {
				impl = append(impl, []string{
					// Peek at the next tag.
					fmt.Sprintf("  uint32 %s_tag = 0;", field.Name),
					fmt.Sprintf("  if (!PeekTag(input, &%s_tag)) return false;", field.Name),
					fmt.Sprintf("  if (!Decode%s(%s_tag, input, &%s_)) return false;", typeName, field.Name, field.Name),
				}...)
				continue
			}
			impl = append(impl, []string{
				fmt.Sprintf("  %s_ = make_unique<%s>();", field.Name, typeName),
				fmt.Sprintf("  if (!%s_->Unmarshal(input)) return false;", field.Name),
			}...)
		case ArrayType:
			if typeName == "byte" {
				impl = append(impl, fmt.Sprintf("  if (!DecodeString(input, &%s_)) return false;", field.Name))
				continue
			}

			impl = append(impl, []string{
				fmt.Sprintf("  uint32 %ss_count = 0;", field.Name),
				fmt.Sprintf("  if (!input->ReadVarint32(&%ss_count)) return false;", field.Name),
				fmt.Sprintf("  for(uint32 i = 0; i < %ss_count; i++) {", field.Name),
			}...)

			if interfaces[typeName] {
				impl = append(impl, []string{
					// Peek at the next tag.
					fmt.Sprintf("    uint32 %ss_tag = 0;", field.Name),
					fmt.Sprintf("    if (!PeekTag(input, &%ss_tag)) return false;", field.Name),
					fmt.Sprintf("    std::unique_ptr<%s> %ss_obj;", typeName, field.Name),
					fmt.Sprintf("    if (!Decode%s(%ss_tag, input, &%ss_obj)) return false;", typeName, field.Name, field.Name),
					fmt.Sprintf("    %ss_.emplace_back(std::move(%ss_obj));", field.Name, field.Name),
					"  }",
				}...)
				continue
			}

			impl = append(impl, []string{
				fmt.Sprintf("    auto %ss_obj = make_unique<%s>();", field.Name, typeName),
				fmt.Sprintf("    %ss_obj->Unmarshal(input);", field.Name),
				fmt.Sprintf("    %ss_.emplace_back(std::move(%ss_obj));", field.Name, field.Name),
				"  }",
			}...)
		}
	}

	return append(impl, "  return true;", "}", "")
}

func writeMarshaller(name string, fields []Field, interfaces map[string]bool) []string {
	impl := []string{fmt.Sprintf(marshalTemplate, name)}
	tag := "BinaryTags::kTag" + name
	impl = append(impl, fmt.Sprintf("  output->WriteVarint32(static_cast<uint32>(%s));", tag))
	for _, field := range fields {
		typeName := field.TypeName

		if typeName == "string" {
			impl = append(impl, fmt.Sprintf("  EncodeString(%s_, output);", field.Name))
			continue
		}

		if typeName == "int" {
			impl = append(impl, fmt.Sprintf("  output->WriteVarint32(%s_);", field.Name))
			continue
		}

		if typeName == "bool" {
			impl = append(impl, fmt.Sprintf("  output->WriteVarint32(static_cast<uint32>(%s_));", field.Name))
			continue
		}

		if typeName == "int64" && field.Type == StarType {
			// This has a boolean value that says whether or
			// not to expect an int64 field next.
			impl = append(impl, []string{
				fmt.Sprintf("  uint32 %s_value = %s_present_ ? 1 : 0;", field.Name, field.Name),
				fmt.Sprintf("  output->WriteVarint32(%s_value);", field.Name),
				fmt.Sprintf("  if (%s_present_) {", field.Name),
				fmt.Sprintf("    output->WriteVarint64(%s_);", field.Name),
				"  }",
			}...)
			continue
		}

		switch field.Type {
		case IdentType:
			impl = append(impl, fmt.Sprintf("  %s_->Marshal(output);", field.Name))
		case ArrayType:
			if typeName == "byte" {
				impl = append(impl, fmt.Sprintf("  EncodeString(%s_, output);", field.Name))
				continue
			}

			impl = append(impl, []string{
				fmt.Sprintf("  output->WriteVarint32(%ss_.size());", field.Name),
				fmt.Sprintf("  for(auto& elt : %ss_) {", field.Name),
				"    elt->Marshal(output);",
				"  }",
			}...)
		}
	}

	return append(impl, "}", "")
}

func writeImplementation(constants []Constant, types map[string][]Field, interfaces map[string]bool, formTypes map[string]bool, termTypes map[string]bool) []string {
	impl := strings.Split(implHeader, "\n")
	impl = append(impl, strings.Split(encodeString, "\n")...)
	impl = append(impl, strings.Split(decodeString, "\n")...)
	impl = append(impl, strings.Split(peekTag, "\n")...)

	impl = append(impl, writeDecoder(constants, "Form", formTypes)...)
	impl = append(impl, writeDecoder(constants, "Term", termTypes)...)
	impl = append(impl, "}  // namespace", "")

	for name, fields := range types {
		impl = append(impl, writeMarshaller(name, fields, interfaces)...)
		impl = append(impl, writeUnmarshaller(name, fields, interfaces, formTypes, termTypes)...)
	}

	return append(impl, "}  // namespace tao")
}

var (
	astFile = flag.String("ast_file", "../../tao/auth/ast.go", "The Go auth AST file to parse")
	binaryFile = flag.String("binary_file", "../../tao/auth/binary.go", "The Go auth binary file to parse")
	headerFile = flag.String("header_file", "auth.h", "The output C++ header to write")
	implFile = flag.String("impl_file", "auth.cc", "The output C++ implementation to write")
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

	tset := token.NewFileSet()
	tf, err := parser.ParseFile(tset, *binaryFile, nil, 0)
	if err != nil {
		log.Fatal(err)
	}

	constantVisitor := &ConstantVisitor{
		Constants: make([]Constant, 0),
	}

	ast.Walk(constantVisitor, tf)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, *astFile, nil, 0)
	if err != nil {
		log.Fatal(err)
	}

	tv := &TypeVisitor{
		ConcreteTypes: make(map[string][]Field),
		InterfaceTypes: make(map[string]bool),
	}
	ast.Walk(tv, f)

	formWalker := &FuncReceiverWalker{
		types: make(map[string]bool),
		name: "isForm",
	}
	ast.Walk(formWalker, f)

	termWalker := &FuncReceiverWalker{
		types: make(map[string]bool),
		name: "isTerm",
	}
	ast.Walk(termWalker, f)

	header := writeHeader(constantVisitor.Constants, tv.ConcreteTypes, tv.InterfaceTypes, formWalker.types, termWalker.types)
	for _, line := range header {
		fmt.Fprintln(headerOutput, line)
	}

	impl := writeImplementation(constantVisitor.Constants, tv.ConcreteTypes, tv.InterfaceTypes, formWalker.types, termWalker.types)
	for _, line := range impl {
		fmt.Fprintln(implOutput, line)
	}
}
