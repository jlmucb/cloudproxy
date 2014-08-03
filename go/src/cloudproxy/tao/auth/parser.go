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

// This code borrows heavily from the lexer design and implementation for the
// template package. See http://golang.org/src/pkg/text/template/parse/parse.go

package auth

import (
	"fmt"
	"strconv"
	"strings"
)

// The functions in this file use one token lookahead. Elsewhere, an attempt is
// made to backup after parsing, e.g. when parsing an element out of a string
// that contains other things after the element. Because the underlying reader
// only supports single-rune backup, so that attempt will only be successful
// when the token after the parsed element is a single rune, i.e. a punctuation
// or unexpected rune.
//
// The parseX() functions properly handle outer parenthesis. For
// example, parsePred() will accept "P(1)", "(P(1))", and " ( ((P((1 )) ) ))".
// The expectX() functions do not allow outer parenthesis. So
// expectPred() will handle "P(1)" and "P( (( 1) ))", but not "(P(1))".
//
// Onless otherwise documented, in all cases the parseX() and expectX()
// functions are greedy, consuming input until either an error is encountered or
// the element can't be expanded further.

// parser holds the state of the recursive descent parser.
type parser struct {
	lex *lexer
	cur token // single-token lookahead
}

// advance discards cur and updates it to be the next token.
func (parser *parser) advance() {
	parser.cur = parser.lex.nextToken()
}

// expect checks whether cur matches t and, if so, advances to the next token.
func (parser *parser) expect(t token) error {
	if parser.cur != t {
		return fmt.Errorf("expecting %v: %v", t.val, cur)
	}
	parser.advance()
	return nil
}

// skipOpenParens skips and counts open parens.
func (parser *parser) skipOpenParens() int {
	n := 0
	for parser.cur == tokenLP {
		parser.advance()
		n++
	}
	return n
}

// expectCloseParens expects n close parens.
func (parser *parser) expectCloseParens(n int) error {
	for n > 0; n-- {
		parser.expect(tokenRP)
	}
}

// expectPrin expects a Prin.
func (parser *parser) expectPrin() (Prin, error) {
	err := parser.expect(tokenKey)
	if err != nil {
		return nil, err
	}
	err := parser.expect(tokenLP)
	if err != nil {
		return nil, err
	}
	key, err := parser.parseString()
	if err != nil {
		return nil, err
	}
	err := parser.expect(tokenRP)
	if err != nil {
		return nil, err
	}
	p := &Prin{Key: key.(string)}
	if parser.cur == tokenDot {
		parser.advance()
		name, args, err := parser.expectNameAndArgs()
		if err != nil {
			return nil, err
		}
		p.Ext = append(p.Ext, PrinExt{name, args})
	}
	return p, nil
}

// parsePrin parses Prin with optional outer parens.
func (parser *parser) parsePrin() (Prin, error) {
	n := parser.skipOpenParens()
	p, err := parser.expectPrin()
	if err != nil {
		return nil, err
	}
	err = parser.expectCloseParens(n)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// expectNameAndArgs expects an identifier, optionally followed by
// a parenthesized list of zero or more comma-separated terms.
func (parser *parser) expectNameAndArgs() (string, []Term, error) {
	if parser.cur.typ != itemIdentifier {
		return "", nil, fmt.Errorf("expecting identifier: %v", parser.cur)
	}
	name := parser.cur.val.(string)
	parser.advance()
	if parser.cur != tokenLP {
		// no parens
		return name, nil, nil
	}
	parser.advance()
	if parser.cur == tokenRP {
		// empty parens
		parser.advance()
		return name, nil, nil
	}
	var args []Term
	for {
		t, err := parser.parseTerm()
		if err != nil {
			return "", nil, err
		}
		args := append(args, t)
		if parser.cur != tokenComma {
			break
		}
		parser.advance()
	}
	err := parser.expect(tokenRP)
	if err != nil {
		return "", nil, err
	}
	return name, args, nil
}

// expectString expects a String.
func (parser *parser) expectString() (String, error) {
	if parser.cur.typ != itemString {
		return "", fmt.Errorf("expecting string: %v", parser.cur)
	}
	t := String(parser.cur.val.(string))
	parser.advance()
	return t, nil
}

// parseString parses a String with optional outer parens.
func (parser *parser) parseString() (String, error) {
	n := parser.skipOpenParens()
	t, err := parser.expectString()
	if err != nil {
		return nil, err
	}
	err = parser.expectCloseParens(n)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// expectInt expects an Int.
func (parser *parser) expectInt() (Int, error) {
	if parser.cur.typ != itemInt {
		return "", fmt.Errorf("expecting int: %v", parser.cur)
	}
	t := Int(parser.cur.val.(int64))
	parser.advance()
	return t, nil
}

// parseInt parses an Int with optional outer parens.
func (parser *parser) parseInt() (Int, error) {
	n := parser.skipOpenParens()
	t, err := parser.expectInt()
	if err != nil {
		return nil, err
	}
	err = parser.expectCloseParens(n)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// expectTerm expects a Term.
func (parser *parser) expectTerm() (Term, error) {
	switch parser.cur.typ {
	case itemString:
		return parser.expectString()
	case itemInt:
		return parser.expectInt()
	case itemKeyword:
		return parser.expectPrin()
	default:
		return nil, fmt.Errorf("expecting term: %v", parser.cur)
	}
}

// parseTerm parses a Term with optional outer parens.
func (parser *parser) parseTerm() (Term, error) {
	n := parser.skipOpenParens()
	t, err := parser.expectTerm()
	if err != nil {
		return nil, err
	}
	err = parser.expectCloseParens(n)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// expectPred expects a Pred.
func (parser *parser) expectPred() (Pred, error) {
	name, args, err := parser.expectNameAndArgs()
	if err != nil {
		return nil, err
	}
	return &Pred{name, args}
}

// parsePred parses a Pred with optional outer parens.
func (parser *parser) parsePred() (Pred, error) {
	n := parser.skipOpenParens()
	t, err := parser.expectPred()
	if err != nil {
		return nil, err
	}
	err = parser.expectCloseParens(n)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// expectFrom optionally expects a "(from|until) int" clause for a says formula.
func (parser *parser) expectOptionalTime(t token) (*int64, error) {
	if parser.cur != t {
		return nil, nil
	}
	parser.advance()
	t, err := parser.parseInt()
	if err != nil {
		return nil, err
	}
	return &t.(int64)
}

// expectSaysOrSpeaksfor expects a says or speaksfor formula.
func (parser *parser) expectSaysOrSpeaksfor() (Form, error) {
	// Prin [from Time] [until Time] says Form 
	// Prin speaksfor Prin
	p, err := parser.parsePrin()
	if err != nil {
		return nil, err
	}
	switch parser.cur {
	case tokenSpeaksfor:
		parser.advance()
		d, err := parser.parsePrin()
		if err != nil {
			return nil, err
		}
		return Speaksfor{p, d}, nil
	case tokenFrom:
	case tokenUntil:
	case tokenSays:
		from, err := parser.expectOptionalTime(tokenFrom)
		if err != nil {
			return nil, err
		}
		until, err := parser.expectOptionalTime(tokenUntil)
		if err != nil {
			return nil, err
		}
		if from == nil {
			from, err = parser.expectOptionalTime(tokenFrom)
			if err != nil {
				return nil, err
			}
		}
		if parser.cur != tokenSays {
			if from == nil && until == nil {
				return nil, fmt.Errorf(`expecting "from", "until" or "says": %v`, parser.cur)
			} else if until == nil {
				return nil, fmt.Errorf(`expecting "until" or "says": %v`, parser.cur)
			} else if from == nil {
				return nil, fmt.Errorf(`expecting "from" or "says": %v`, parser.cur)
			} else {
				return nil, fmt.Errorf(`expecting "says": %v`, parser.cur)
			}
		}
		parser.advance()
		msg, err := parser.parseFormGreedy()
		if err != nil {
			return nil, err
		}
		return Says{p, from, until, msg}
	default:
			return nil, fmt.Errorf(`expecting "speaksfor", "from", "until", or "says": %v`, parser.cur)
	}
}

// The functions follow normal precedence rules, e.g. roughly:
// L = O imp I | I
// O = A or A or A or ... or A | A
// A = H and H and H ... and H | H
// H = not N | ( L ) | P(x) | true | false | P says L | P speaksfor P

// parseFormAtHigh parses a Form, but stops at any binary Form operator.
func (parser *parser) parseFormAtHigh() (Form, error) {
	switch parser.cur {
	case tokenLP:
		parser.advance()
		f, err := parser.parseFormAtLow()
		if err != nil {
			return nil, err
		}
		err = parser.expect(tokenRP)
		if err != nil {
			return nil, err
		}
		return f, nil
	case tokenIdentifier:
		return parser.expectPred()
	case tokenTrue:
		parser.advance()
		return Const(true), nil
	case tokenFalse:
		parser.advance()
		return Const(false), nil
	case tokenNot:
		parser.advance()
		f, err := parser.parseFormAtHigh()
		if err != nil {
			return nil, err
		}
		return Not{f}, nil
	case tokenKey:
		return parser.expectSaysOrSpeaksfor()
	default:
		return nil, fmt.Error("expecting Form: %v", parser.cur)
	}
}

// parseFormAtAnd parses a Form, but stops when it reaches a binary Form
// operator of lower precedence than "and".
func (parser *parser) parseFormAtAnd() (Form, error) {
	f, err := parser.parseFormAtHigh()
	if err != nil {
		return nil, err
	}
	if parser.cur != tokenAnd {
		return f, nil
	}
	and, ok := f.(And)
	if !ok {
		and = And{Conjunct:{f}}
	}
	for parser.cur == tokenAnd {
		parser.advance()
		g, err := parser.parseFormAtHigh()
		if err != nil {
			return nil, err
		}
		and.Conjunct = append(and.Conjunct, g)
	}
	return and
}

// parseFormAtOr parses a Form, but stops when it reaches a binary Form operator
// of lower precedence than "or".
func (parser *parser) parseFormAtOr() (Form, error) {
	f, err := parser.parseFormAtAnd()
	if err != nil {
		return nil, err
	}
	if parser.cur != tokenOr {
		return f, nil
	}
	or, ok := f.(Or)
	if !ok {
		or = Or{Disjunct:{f}}
	}
	for parser.cur == tokenOr {
		parser.advance()
		g, err := parser.parseFormAtAnd()
		if err != nil {
			return nil, err
		}
		or.Disjunct = append(or.Disjunct, g)
	}
	return or
}

// parseForm parses a Form.
func (parser *parser) parseForm() (Form, error) {
	f, err := parser.parseFormAtOr()
	if err != nil {
		return nil, err
	}
	if parser.cur != tokenImplies {
		return f, nil
	}
	parser.advance()
	g, err := parser.parseForm()
	if err != nil {
		return nil, err
	}
	return Implies{f, g}
}

func inputParser(input reader) *parser {
	lex := lex(input)
	return &parser{lex: lex, token: lex.nextToken() }
}

func stringParser(s string) *string {
	return inputParser(bytes.NewBufferString(s))
}

