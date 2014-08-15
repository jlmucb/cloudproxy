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

// This code borrows heavily from the parser design and implementation for the
// template package. See http://golang.org/src/pkg/text/template/parse/parse.go
//
// It also borrows from the parser in package
// github.com/kevinawalsh/datalog/dlengine
// licensed by the author here under the above Apache License, Version 2.0.

package auth

import (
	"encoding/base64"
	"fmt"
)

// The functions in this file use one token lookahead, but only when more input
// is actually called for. The lexer may read one rune ahead while getting a
// token, but will unread that rune when the token is completed. The goal is to
// allow parsing an element out of a string or input stream that contains other
// data after the element.
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
	lex           *lexer
	lookahead     token
	haveLookahead bool
}

// cur advances the lexer if needed and returns the first unprocessed token.
func (p *parser) cur() token {
	if !p.haveLookahead {
		p.lookahead = p.lex.nextToken()
		p.haveLookahead = true
	}
	return p.lookahead
}

// advance discards lookahead; the next call to cur() will get a new token.
func (p *parser) advance() {
	// if !p.haveLookahead {
	// 	panic("advance should only be called when there is a current token")
	// }
	p.haveLookahead = false
}

// expect checks whether cur matches t and, if so, advances to the next token.
func (p *parser) expect(t token) error {
	if p.cur() != t {
		return fmt.Errorf("expected %q, found %v", t.val, p.cur())
	}
	p.advance()
	return nil
}

// skipOpenParens skips and counts open parens.
func (p *parser) skipOpenParens() int {
	var n int
	for n = 0; p.cur() == tokenLP; n++ {
		p.advance()
	}
	return n
}

// expectCloseParens expects n close parens.
func (p *parser) expectCloseParens(n int) error {
	for n > 0 {
		err := p.expect(tokenRP)
		if err != nil {
			return err
		}
		n--
	}
	return nil
}

// expectPrin expects a Prin.
func (p *parser) expectPrin() (prin Prin, err error) {
	if p.cur() != tokenTPM && p.cur() != tokenKey {
		err = fmt.Errorf(`expected "key" or "tpm", found %v`, p.cur())
		return
	}
	prin.Type = p.cur().val.(string)
	p.advance()
	if r := p.lex.peek(); r != '(' {
		err = fmt.Errorf(`expected '(' directly after "key", found %q`, r)
		return
	}
	err = p.expect(tokenLP)
	if err != nil {
		return
	}
	key, err := p.parseStr()
	if err != nil {
		return
	}
	err = p.expect(tokenRP)
	if err != nil {
		return
	}
	prin.Key, err = base64.URLEncoding.DecodeString(string(key))
	if err != nil {
		return
	}
	for p.lex.peek() == '.' {
		prin.Ext, err = p.expectSubPrin()
	}
	return
}

// parsePrin parses a Prin with optional outer parens.
func (p *parser) parsePrin() (prin Prin, err error) {
	n := p.skipOpenParens()
	prin, err = p.expectPrin()
	if err != nil {
		return
	}
	err = p.expectCloseParens(n)
	return
}

// expectSubPrin expects a SubPrin.
func (p *parser) expectSubPrin() (s SubPrin, err error) {
	if p.cur() != tokenDot {
		err = fmt.Errorf(`expected '.', found %v`, p.cur())
		return
	}
	p.advance()
	name, args, err := p.expectNameAndArgs()
	if err != nil {
		return
	}
	s = append(s, PrinExt{name, args})
	for p.lex.peek() == '.' {
		if p.cur() != tokenDot {
			panic("not reached")
		}
		p.advance()
		name, args, err = p.expectNameAndArgs()
		if err != nil {
			return
		}
		s = append(s, PrinExt{name, args})
	}
	return
}

// expectNameAndArgs expects an identifier, optionally followed by
// a parenthesized list of zero or more comma-separated terms.
func (p *parser) expectNameAndArgs() (string, []Term, error) {
	if p.cur().typ != itemIdentifier {
		return "", nil, fmt.Errorf("expected identifier, found %v", p.cur())
	}
	name := p.cur().val.(string)
	p.advance()
	if p.lex.peek() != '(' {
		// no parens
		return name, nil, nil
	}
	if p.cur() != tokenLP {
		panic("not reached")
	}
	p.advance()
	if p.cur() == tokenRP {
		// empty parens
		p.advance()
		return name, nil, nil
	}
	var args []Term
	for {
		t, err := p.parseTerm()
		if err != nil {
			return "", nil, err
		}
		args = append(args, t)
		if p.cur() != tokenComma {
			break
		}
		p.advance()
	}
	err := p.expect(tokenRP)
	if err != nil {
		return "", nil, err
	}
	return name, args, nil
}

// expectStr expects a Str.
func (p *parser) expectStr() (Str, error) {
	if p.cur().typ != itemStr {
		return "", fmt.Errorf("expected string, found %v", p.cur())
	}
	t := Str(p.cur().val.(string))
	p.advance()
	return t, nil
}

// parseStr parses a Str with optional outer parens.
func (p *parser) parseStr() (t Str, err error) {
	n := p.skipOpenParens()
	t, err = p.expectStr()
	if err != nil {
		return
	}
	err = p.expectCloseParens(n)
	return
}

// expectInt expects an Int.
func (p *parser) expectInt() (Int, error) {
	if p.cur().typ != itemInt {
		return 0, fmt.Errorf("expected int, found %v", p.cur())
	}
	t := Int(p.cur().val.(int64))
	p.advance()
	return t, nil
}

// parseInt parses an Int with optional outer parens.
func (p *parser) parseInt() (Int, error) {
	n := p.skipOpenParens()
	t, err := p.expectInt()
	if err != nil {
		return 0, err
	}
	err = p.expectCloseParens(n)
	if err != nil {
		return 0, err
	}
	return t, nil
}

// expectTerm expects a Term.
func (p *parser) expectTerm() (Term, error) {
	switch p.cur().typ {
	case itemStr:
		return p.expectStr()
	case itemInt:
		return p.expectInt()
	case itemKeyword:
		return p.expectPrin()
	default:
		return nil, fmt.Errorf("expected term, found %v", p.cur())
	}
}

// parseTerm parses a Term with optional outer parens.
func (p *parser) parseTerm() (Term, error) {
	n := p.skipOpenParens()
	t, err := p.expectTerm()
	if err != nil {
		return nil, err
	}
	err = p.expectCloseParens(n)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// expectPred expects a Pred.
func (p *parser) expectPred() (f Pred, err error) {
	name, args, err := p.expectNameAndArgs()
	if err != nil {
		return
	}
	return Pred{name, args}, nil
}

// parsePred parses a Pred with optional outer parens.
func (p *parser) parsePred() (f Pred, err error) {
	n := p.skipOpenParens()
	f, err = p.expectPred()
	if err != nil {
		return
	}
	err = p.expectCloseParens(n)
	return
}

// expectConst expects a Const.
func (p *parser) expectConst() (f Const, err error) {
	if p.cur() != tokenTrue && p.cur() != tokenFalse {
		err = fmt.Errorf("expected Const, found %v", p.cur())
		return
	}
	f = Const(p.cur() == tokenTrue)
	p.advance()
	return
}

// parseConst parses a Const with optional outer parens.
func (p *parser) parseConst() (f Const, err error) {
	n := p.skipOpenParens()
	f, err = p.expectConst()
	if err != nil {
		return
	}
	err = p.expectCloseParens(n)
	return
}

// expectFrom optionally expects a "(from|until) int" clause for a says formula.
func (p *parser) expectOptionalTime(t token) (*int64, error) {
	if p.cur() != t {
		return nil, nil
	}
	p.advance()
	i, err := p.parseInt()
	if err != nil {
		return nil, err
	}
	val := int64(i)
	return &val, nil
}

// expectSaysOrSpeaksfor expects a says or speaksfor formula. If greedy is true,
// this will parse as much input as possible. Otherwise, it will take only as
// much input as needed to make a valid formula.
func (p *parser) expectSaysOrSpeaksfor(greedy bool) (Form, error) {
	// Prin [from Time] [until Time] says Form
	// Prin speaksfor Prin
	prin, err := p.parsePrin()
	if err != nil {
		return nil, err
	}
	switch p.cur() {
	case tokenSpeaksfor:
		p.advance()
		d, err := p.parsePrin()
		if err != nil {
			return nil, err
		}
		return Speaksfor{prin, d}, nil
	case tokenFrom, tokenUntil, tokenSays:
		from, err := p.expectOptionalTime(tokenFrom)
		if err != nil {
			return nil, err
		}
		until, err := p.expectOptionalTime(tokenUntil)
		if err != nil {
			return nil, err
		}
		if from == nil {
			from, err = p.expectOptionalTime(tokenFrom)
			if err != nil {
				return nil, err
			}
		}
		if p.cur() != tokenSays {
			if from == nil && until == nil {
				return nil, fmt.Errorf(`expected "from", "until" or "says", found %v`, p.cur())
			} else if until == nil {
				return nil, fmt.Errorf(`expected "until" or "says", found %v`, p.cur())
			} else if from == nil {
				return nil, fmt.Errorf(`expected "from" or "says", found %v`, p.cur())
			} else {
				return nil, fmt.Errorf(`expected "says", found %v`, p.cur())
			}
		}
		p.advance()
		var msg Form
		if greedy {
			msg, err = p.parseForm()
		} else {
			msg, err = p.parseFormAtHigh(true)
		}
		if err != nil {
			return nil, err
		}
		return Says{prin, from, until, msg}, nil
	default:
		return nil, fmt.Errorf(`expected "speaksfor", "from", "until", or "says", found %v`, p.cur())
	}
}

// The functions follow normal precedence rules, e.g. roughly:
// L = O imp I | I
// O = A or A or A or ... or A | A
// A = H and H and H ... and H | H
// H = not N | ( L ) | P(x) | true | false | P says L | P speaksfor P

// parseFormAtHigh parses a Form, but stops at any binary Form operator. If
// greedy is true, this will parse as much input as possible. Otherwise, it will
// parse only as much input as needed to make a valid formula.
func (p *parser) parseFormAtHigh(greedy bool) (Form, error) {
	switch p.cur() {
	case tokenLP:
		p.advance()
		f, err := p.parseForm()
		if err != nil {
			return nil, err
		}
		err = p.expect(tokenRP)
		if err != nil {
			return nil, err
		}
		return f, nil
	case tokenTrue, tokenFalse:
		return p.expectConst()
	case tokenNot:
		p.advance()
		f, err := p.parseFormAtHigh(greedy)
		if err != nil {
			return nil, err
		}
		return Not{f}, nil
	case tokenKey, tokenTPM:
		return p.expectSaysOrSpeaksfor(greedy)
	default:
		if p.cur().typ == itemIdentifier {
			return p.expectPred()
		}
		return nil, fmt.Errorf("expected Form, found %v", p.cur())
	}
}

// parseFormAtAnd parses a Form, but stops when it reaches a binary Form
// operator of lower precedence than "and".
func (p *parser) parseFormAtAnd() (Form, error) {
	f, err := p.parseFormAtHigh(true)
	if err != nil {
		return nil, err
	}
	if p.cur() != tokenAnd {
		return f, nil
	}
	and, ok := f.(And)
	if !ok {
		and = And{Conjunct: []Form{f}}
	}
	for p.cur() == tokenAnd {
		p.advance()
		g, err := p.parseFormAtHigh(true)
		if err != nil {
			return nil, err
		}
		and.Conjunct = append(and.Conjunct, g)
	}
	return and, nil
}

// parseFormAtOr parses a Form, but stops when it reaches a binary Form operator
// of lower precedence than "or".
func (p *parser) parseFormAtOr() (Form, error) {
	f, err := p.parseFormAtAnd()
	if err != nil {
		return nil, err
	}
	if p.cur() != tokenOr {
		return f, nil
	}
	or, ok := f.(Or)
	if !ok {
		or = Or{Disjunct: []Form{f}}
	}
	for p.cur() == tokenOr {
		p.advance()
		g, err := p.parseFormAtAnd()
		if err != nil {
			return nil, err
		}
		or.Disjunct = append(or.Disjunct, g)
	}
	return or, nil
}

// parseForm parses a Form. This function is greedy: it consumes as much input
// as possible until either an error or EOF is encountered.
func (p *parser) parseForm() (Form, error) {
	f, err := p.parseFormAtOr()
	if err != nil {
		return nil, err
	}
	if p.cur() != tokenImplies {
		return f, nil
	}
	p.advance()
	g, err := p.parseForm()
	if err != nil {
		return nil, err
	}
	return Implies{f, g}, nil
}

// parseShortestForm parses the shortest valid Form. This function is not
// greedy: it consumes only as much input as necessary to obtain a valid
// formula. For example, "(p says a and b ...)" and "p says (a and b ...) will
// be parsed in their entirety, but given "p says a and b ... ", only "p says a"
// will be parsed.
func (p *parser) parseShortestForm() (Form, error) {
	return p.parseFormAtHigh(false)
}

func newParser(input reader) *parser {
	lex := lex(input)
	return &parser{lex: lex}
}
