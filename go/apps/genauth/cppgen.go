package genauth

import (
	"fmt"
	"strings"
)

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
	marshalTemplate   = "void %s::Marshal(CodedOutputStream* output) {"

	headerPrefix = `#ifndef CLOUDPROXY_GO_APPS_GENAUTH_H_
#define CLOUDPROXY_GO_APPS_GENAUTH_H_
#include <memory>
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
)

// CppGenerator generates C++ code from the Go auth types.
type CppGenerator struct {
	Constants  []Constant
	Types      map[string][]Field
	Interfaces map[string]bool
	FormTypes  map[string]bool
	TermTypes  map[string]bool
}

// Constants creates lines that define the constants for auth serialization and
// deserialization.
func (cg *CppGenerator) BinaryConstants() []string {
	header := []string{"enum class BinaryTags {"}
	for i, constant := range cg.Constants {
		value := fmt.Sprintf("  %s = %d", constant.Name, constant.Value)
		if i < len(cg.Constants)-1 {
			value += ","
		}
		header = append(header, value)
	}
	return append(header, "};", "")
}

// FieldDeclType returns a string that represents the C++ type for this field.
func FieldDeclType(info Field) string {
	typeName := info.TypeName

	if primitives[typeName] {
		if info.Type == StarType {
			typeName = typeName + "*"
		}

		if typeName == "string" {
			typeName = "std::string"
		}

		if typeName == "int64*" {
			// This is not a pointer in the C++ version. The type change is needed to get the CodedInputStream unmarshalling to work.
			typeName = "google::protobuf::uint64"
		}

		if typeName == "int" {
			// The type change is needed to get the CodedInputStream unmarshalling to work.
			typeName = "google::protobuf::uint32"
		}

		return typeName
	}

	switch info.Type {
	case IdentType, StarType:
		return fmt.Sprintf("std::unique_ptr<%s>", typeName)
	case ArrayType:
		if info.TypeName == "byte" {
			return "std::string"
		}

		return "std::vector<std::unique_ptr<" + typeName + ">>"
	}

	return ""
}

// FieldName returns the generated name for a field in an auth class.
func FieldName(info Field) string {
	varName := info.Name + "_"
	if info.Type == ArrayType && info.TypeName != "byte" {
		varName = info.Name + "s_";
	}

	return varName
}

// FieldDecl generates the code for a field in a C++ header.
func FieldDecl(info Field) []string {
	field := make([]string, 0)
	fieldType := FieldDeclType(info)
	if info.Type == StarType {
		field = append(field, fmt.Sprintf("  bool %s_present_;", info.Name))
	}

	return append(field, "  " + fieldType + " " + FieldName(info) + ";")
}

func (cg *CppGenerator) Class(name string, fields []Field) []string {
	class := fmt.Sprintf("class %s", name)
	isSubclass := false
	if _, isForm := cg.FormTypes[name]; isForm {
		class += ": public Form"
		isSubclass = true
	} else if _, isTerm := cg.TermTypes[name]; isTerm {
		class += ": public Term"
		isSubclass = true
	}

	class += " {"
	header := []string{class, " public:"}

	header = append(header, fmt.Sprintf("  %s() = default;", name))
	var override string
	if isSubclass {
		override = " override"
	}

	rvalue := fmt.Sprintf("  %s(", name)

	marshal := "  void Marshal(google::protobuf::io::CodedOutputStream* output)"
	unmarshal := "  bool Unmarshal(google::protobuf::io::CodedInputStream* input)"

	header = append(header, fmt.Sprintf("  ~%s()%s = default;", name, override))
	header = append(header, fmt.Sprintf("%s%s;", marshal, override))
	header = append(header, fmt.Sprintf("%s%s;", unmarshal, override))

	variables := make([]string, 0)
	for i, info := range fields {
		variables = append(variables, FieldDecl(info)...)

		rvalue += FieldDeclType(info) + "&& " + FieldName(info)
		if i < len(fields) - 1 {
			rvalue += ", "
		} else {
			rvalue += ");"
		}
	}

	header = append(header, rvalue)
	header = append(header, variables...)

	return append(header, "};", "")
}

// Header creates the header file for the C++ code.
func (cg *CppGenerator) Header() []string {
	header := strings.Split(headerPrefix, "\n")
	header = append(header, cg.BinaryConstants()...)

	// Append declarations of all the class to avoid ordering problems.
	for name, _ := range cg.Types {
		header = append(header, "class "+name+";")
	}
	header = append(header, "")

	for name, fields := range cg.Types {
		header = append(header, cg.Class(name, fields)...)
	}

	return append(header, "}  // namespace tao", "#endif  // CLOUDPROXY_GO_APPS_GENAUTH_H_")
}

// Decoder generates code that deserializes bytes that might be any subclass of
// a given interface class.
func (cg *CppGenerator) Decoder(interfaceName string, types map[string]bool) []string {
	impl := []string{
		"bool Decode" + interfaceName + "(uint32 tag, CodedInputStream* input, std::unique_ptr<" + interfaceName + ">* value) {",
		"  switch(tag) {",
	}
	for _, constant := range cg.Constants {
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

// PrimitiveUnmarshaller generates code that unmarshals primitive types like int.
func PrimitiveUnmarshaller(typeName string, field Field) []string {
	if typeName == "string" {
		return []string{fmt.Sprintf("  if (!DecodeString(input, &%s_)) return false;", field.Name)}
	}

	if typeName == "int" {
		return []string{fmt.Sprintf("  if (!input->ReadVarint32(&%s_)) return false;", field.Name)}
	}

	if typeName == "bool" {
		return []string{
			fmt.Sprintf("  uint32 %s_value = 0;", field.Name),
			fmt.Sprintf("  if (!input->ReadVarint32(&%s_value)) return false;", field.Name),
			fmt.Sprintf("  %[1]s_ = !!%[1]s_value;", field.Name),
		}
	}

	if typeName == "int64" && field.Type == StarType {
		// This has a boolean value that says whether or
		// not to expect an int64 field next.
		return []string{
			fmt.Sprintf("  uint32 %s_present_value = 0;", field.Name),
			fmt.Sprintf("  if (!input->ReadVarint32(&%s_present_value)) return false;", field.Name),
			fmt.Sprintf("  %[1]s_present_ = !!%[1]s_present_value;", field.Name),
			fmt.Sprintf("  if (%s_present_) {", field.Name),
			fmt.Sprintf("    if (!input->ReadVarint64(&%s_)) return false;", field.Name),
			"  }",
		}
	}

	return nil
}

// IdentUnmarshaller generates code that unmarshals an ast.Ident.
func (cg *CppGenerator) IdentUnmarshaller(typeName string, field Field) []string {
	if cg.Interfaces[typeName] {
		return []string{
			// Peek at the next tag.
			fmt.Sprintf("  uint32 %s_tag = 0;", field.Name),
			fmt.Sprintf("  if (!PeekTag(input, &%s_tag)) return false;", field.Name),
			fmt.Sprintf("  if (!Decode%s(%[2]s_tag, input, &%[2]s_)) return false;", typeName, field.Name),
		}
	}
	return []string{
		fmt.Sprintf("  %s_ = make_unique<%s>();", field.Name, typeName),
		fmt.Sprintf("  if (!%s_->Unmarshal(input)) return false;", field.Name),
	}
}

// ArrayUnmarshaller generates code that unmarshals an Array.
func (cg *CppGenerator) ArrayUnmarshaller(typeName string, field Field) []string {
	if typeName == "byte" {
		return []string{fmt.Sprintf("  if (!DecodeString(input, &%s_)) return false;", field.Name)}
	}

	impl := []string{
		fmt.Sprintf("  uint32 %ss_count = 0;", field.Name),
		fmt.Sprintf("  if (!input->ReadVarint32(&%ss_count)) return false;", field.Name),
		fmt.Sprintf("  for(uint32 i = 0; i < %ss_count; i++) {", field.Name),
	}

	if cg.Interfaces[typeName] {
		return append(impl, []string{
			// Peek at the next tag.
			fmt.Sprintf("    uint32 %ss_tag = 0;", field.Name),
			fmt.Sprintf("    if (!PeekTag(input, &%ss_tag)) return false;", field.Name),
			fmt.Sprintf("    std::unique_ptr<%s> %ss_obj;", typeName, field.Name),
			fmt.Sprintf("    if (!Decode%s(%[2]ss_tag, input, &%[2]ss_obj)) return false;", typeName, field.Name),
			fmt.Sprintf("    %[1]ss_.emplace_back(std::move(%[1]ss_obj));", field.Name),
			"  }",
		}...)
	}

	return append(impl, []string{
		fmt.Sprintf("    auto %ss_obj = make_unique<%s>();", field.Name, typeName),
		fmt.Sprintf("    %ss_obj->Unmarshal(input);", field.Name),
		fmt.Sprintf("    %[1]ss_.emplace_back(std::move(%[1]ss_obj));", field.Name),
		"  }",
	}...)
}

// Unmarshaller generates code that unmarshals bytes to a given class.
func (cg *CppGenerator) Unmarshaller(name string, fields []Field) []string {
	impl := []string{fmt.Sprintf(unmarshalTemplate, name)}
	tag := "BinaryTags::kTag" + name
	impl = append(impl, []string{
		"  uint32 type_tag = 0;",
		"  if (!input->ReadVarint32(&type_tag)) return false;",
		fmt.Sprintf("  if (type_tag != static_cast<uint32>(%s)) return false;", tag),
	}...)
	for _, field := range fields {
		typeName := field.TypeName
		if primitives[typeName] {
			m := PrimitiveUnmarshaller(typeName, field)
			if m != nil {
				impl = append(impl, m...)
			}
			continue
		}

		switch field.Type {
		case IdentType:
			impl = append(impl, cg.IdentUnmarshaller(typeName, field)...)
		case ArrayType:
			impl = append(impl, cg.ArrayUnmarshaller(typeName, field)...)
		}
	}

	return append(impl, "  return true;", "}", "")
}

// PrimitiveMarshaller generates serialization code for primitive types like int.
func (cg *CppGenerator) PrimitiveMarshaller(typeName string, field Field) []string {
	if typeName == "string" {
		return []string{fmt.Sprintf("  EncodeString(%s_, output);", field.Name)}
	}

	if typeName == "int" {
		return []string{fmt.Sprintf("  output->WriteVarint32(%s_);", field.Name)}
	}

	if typeName == "bool" {
		return []string{fmt.Sprintf("  output->WriteVarint32(static_cast<uint32>(%s_));", field.Name)}
	}

	if typeName == "int64" && field.Type == StarType {
		// This has a boolean value that says whether or
		// not to expect an int64 field next.
		return []string{
			fmt.Sprintf("  uint32 %[1]s_value = %[1]s_present_ ? 1 : 0;", field.Name),
			fmt.Sprintf("  output->WriteVarint32(%s_value);", field.Name),
			fmt.Sprintf("  if (%s_present_) {", field.Name),
			fmt.Sprintf("    output->WriteVarint64(%s_);", field.Name),
			"  }",
		}
	}

	return nil
}

// MoveConstructor generates a constructor that moves all of the member
// variables through rvalue parameters.
func (cg *CppGenerator) MoveConstructor(name string, fields []Field) []string {
	sig := fmt.Sprintf("%[1]s::%[1]s(", name)
	body := make([]string, 0)
	for i, info := range fields {
		sig += FieldDeclType(info) + "&& " + info.Name
		end := ""
		if i < len(fields) - 1 {
			sig += ", "
			end = ","
		} else {
			sig += ")"
			end = " {}\n"
		}

		leader := "    "
		if i == 0 {
			leader += ": "
		}
		body = append(body, fmt.Sprintf("%s%s(std::move(%s))%s", leader, FieldName(info), info.Name, end))
	}

	header := []string{sig}
	return append(header, body...)
}

// Marshaller generates serialization code for the given auth type.
func (cg *CppGenerator) Marshaller(name string, fields []Field) []string {
	impl := []string{fmt.Sprintf(marshalTemplate, name)}
	tag := "BinaryTags::kTag" + name
	impl = append(impl, fmt.Sprintf("  output->WriteVarint32(static_cast<uint32>(%s));", tag))
	for _, field := range fields {
		typeName := field.TypeName

		if primitives[typeName] {
			m := cg.PrimitiveMarshaller(typeName, field)
			if m != nil {
				impl = append(impl, m...)
			}
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

// Implementation generates the C++ implementation file for the auth classes.
func (cg *CppGenerator) Implementation() []string {
	impl := strings.Split(implHeader, "\n")
	impl = append(impl, strings.Split(encodeString, "\n")...)
	impl = append(impl, strings.Split(decodeString, "\n")...)
	impl = append(impl, strings.Split(peekTag, "\n")...)

	impl = append(impl, cg.Decoder("Form", cg.FormTypes)...)
	impl = append(impl, cg.Decoder("Term", cg.TermTypes)...)
	impl = append(impl, "}  // namespace", "")

	for name, fields := range cg.Types {
		impl = append(impl, cg.MoveConstructor(name, fields)...)
		impl = append(impl, cg.Marshaller(name, fields)...)
		impl = append(impl, cg.Unmarshaller(name, fields)...)
	}

	return append(impl, "}  // namespace tao")
}
