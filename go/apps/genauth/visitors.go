package genauth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"strings"
)

var primitives = map[string]bool{
	"bool":   true,
	"int":    true,
	"int64":  true,
	"string": true,
}

// FieldType describes the AST type of a field in a struct.
type FieldType int

// The constants are the AST types that this code uses.
const (
	IdentType FieldType = iota
	StarType
	ArrayType
)

// Field represents a field of a struct.
type Field struct {
	Name     string
	Type     FieldType
	TypeName string
}

// TypeVisitor visits ast.Nodes and finds all the types that need code
// generation.
type TypeVisitor struct {
	ConcreteTypes  map[string][]Field
	InterfaceTypes map[string]bool
}

// FieldVisitor visits all the fields of a struct found by TypeVisitor and
// records them.
type FieldVisitor struct {
	ConcreteTypes  map[string][]Field
	InterfaceTypes map[string]bool
	Name           string
}

// Visit examines a Node and records its type if it matches a type that this
// code handles.
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
			ConcreteTypes:  tv.ConcreteTypes,
			InterfaceTypes: tv.InterfaceTypes,
			Name:           name,
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

// Visit examines an ast.Field node and records it name and type.
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
		ConcreteTypes:  fv.ConcreteTypes,
		InterfaceTypes: fv.InterfaceTypes,
	}
}

// FuncReceiverWalker holds information about the receiver types in the AST.
type FuncReceiverWalker struct {
	types map[string]bool
	name  string
}

// Visit handles a node in the AST and records the receiver type, if any.
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

// Constant represents a constant value in the file.
type Constant struct {
	Name  string
	Value int
}

// ConstantVisitor stores a list of constants from the file.
type ConstantVisitor struct {
	Constants []Constant
}

// Visit handles an ast.Node and records it if this node is a constant.
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

func ParseAuthAst(binaryFile, astFile string) *CppGenerator {
	tset := token.NewFileSet()
	tf, err := parser.ParseFile(tset, binaryFile, nil, 0)
	if err != nil {
		log.Fatal(err)
	}

	constantVisitor := &ConstantVisitor{
		Constants: make([]Constant, 0),
	}

	ast.Walk(constantVisitor, tf)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, astFile, nil, 0)
	if err != nil {
		log.Fatal(err)
	}

	tv := &TypeVisitor{
		ConcreteTypes:  make(map[string][]Field),
		InterfaceTypes: make(map[string]bool),
	}
	ast.Walk(tv, f)

	formWalker := &FuncReceiverWalker{
		types: make(map[string]bool),
		name:  "isForm",
	}
	ast.Walk(formWalker, f)

	termWalker := &FuncReceiverWalker{
		types: make(map[string]bool),
		name:  "isTerm",
	}
	ast.Walk(termWalker, f)

	return &CppGenerator{
		Constants:  constantVisitor.Constants,
		Types:      tv.ConcreteTypes,
		Interfaces: tv.InterfaceTypes,
		FormTypes:  formWalker.types,
		TermTypes:  termWalker.types,
	}
}
