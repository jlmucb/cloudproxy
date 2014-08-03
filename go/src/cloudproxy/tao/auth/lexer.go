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

package auth

import (
	"bytes"
	"fmt"
	"io"
	"unicode"
)

// token is a value returned from the lexer.
type token struct {
	typ itemType
	val interface{} // string, int64, error, or nil
}

// itemType identifies the type of lex items.
type itemType int

const (
	itemError itemType = iota // value contains error
	itemUnexpectedRune        // value contains the rune
	itemEOF                   // value is nil
	itemKeyword               // value contains the keyword
	itemIdentifier            // value contains the identifer
	itemString                // value contains the string
	itemInt                   // value contains the int64
	itemLP                    // value contains '('
	itemRP                    // value contains ')'
	itemComma                 // value contains ','
	itemDot                   // value contains '.'
)

const (
  tokenFrom = token{itemKeyword, "from"}
  tokenUntil = token{itemKeyword, "until"}
  tokenSays = token{itemKeyword, "says"}
  tokenSpeaskfor = token{itemKeyword, "speaskfor"}
  tokenImplies = token{itemKeyword, "implies"}
  tokenOr = token{itemKeyword, "or"}
  tokenAnd = token{itemKeyword, "and"}
  tokenNot = token{itemKeyword, "not"}
  tokenFalse = token{itemKeyword, "false"}
  tokenTrue = token{itemKeyword, "true"}
  tokenKey = token{itemKeyword, "key"}
	tokenLP = token{itemLP, '('}
	tokenRP = token{itemRP, ')'}
	tokenComma = token{itemComma, ','}
	tokenDot = token{itemDot, '.'}
	tokenEOF = token{itemEOF, nil}
)

// String returns pretty-printed token, e.g. for debugging.
func (i token) String() string {
	switch i.typ {
	case itemError:
		return fmt.Sprintf("Error{%v}", i.val)
	case itemUnexpectedRune:
		return fmt.Sprintf("UnexpectedRune{%v}", i.val)
	case itemEOF:
		return "EOF{}"
	case itemKeyword:
		return fmt.Sprintf("Keyword{%q}", i.val)
	case itemIdentifier:
		return fmt.Sprintf("Identifier{%q}", i.val)
	case itemString:
		return fmt.Sprintf("String{%q}", i.val)
	case itemInt:
		return fmt.Sprintf("Int{%v}", i.val)
	case itemLP, itemRP, itemComma, itemDot:
		return fmt.Sprintf("Punct{%q}", i.val)
	default:
		panic("not reached")
	}
}

// reader provides input to the scanner.
type reader interface {
	io.RuneScanner // for ReadRune, UnreadRune
	io.Reader      // for Fscanf
}

// lexer holds the state of the scanner.
type lexer struct {
	input reader       // the input being scanned.
	val   bytes.Buffer // accumulated runes returned from next().
	width int          // width of last rune returned from next().
	done  *token       // token found at end of input.
}

const eof rune = 0

func (l *lexer) lexMain() token {
	for {
		switch r := l.next(); {
		case r == eof:
			return tokenEOF
		case unicode.IsSpace(r):
			l.reset()
		case r == '(':
			return token{itemLP, r}
		case r == ')':
			return token{itemRP, r}
		case r == '\'':
			return token{itemComma, r}
		case r == '.':
			return token{itemDot, r}
		case r == '"':
			l.backup()
			return l.lexString()
		case r == '-' || digit(r):
			l.backup()
			return l.lexInt()
		case lower(r):
			l.backup()
			return l.lexKeyword()
		case upper(r):
			l.backup()
			return l.lexIdentifier()
		default:
			l.backup()
			return token{itemUnexpectedRune, r}
		}
	}
}

func (l *lexer) lexString() token {
	var s string
	_, err := fmt.Fscanf(l.input, "%q", &s)
	if err != nil {
		return token{itemError, err}
	}
	return token{itemString, s}
}

func (l *lexer) lexInt() token {
	var i int64
	_, err := fmt.Fscanf(l.input, "%d", &i)
		return token{itemError, err}
	}
	return token{itemInt, i}
}

func (l *lexer) lexKeyword() token {
	for {
		r := l.next()
		if !lower(r) {
			l.backup()
			return token{itemKeyword, l.reset()}
		}
	}
}

func lexIdentifier(l *lexer) stateFn {
	// precondition: l.next() is [A-Z]
	for {
		r := l.next()
		if !(lower(r) || upper(r) || digit(r) || r == '_') {
			l.backup()
			return token{itemIdentifier, l.reset()}
		}
	}
}

func digit(r rune) bool {
	return '0' <= r <= '9'
}

func lower(r rune) bool {
	return 'a' <= r <= 'z'
}

func upper(r rune) bool {
	return 'a' <= r <= 'Z'
}

// next returns the next rune in the input.
func (l *lexer) next() (r rune) {
	r, n, err := l.input.ReadRune()
	if err == io.EOF {
		return eof
	}
	l.val.WriteRune(r)
	l.width = n
	return r
}

// backup steps back one rune. Can be called only once per call of next.
func (l *lexer) backup() {
	l.input.UnreadRune()
	l.val.Truncate(l.val.Len() - l.width)
	l.width = 0
}

// reset consumes accumulated input and resets val and width.
func (l *lexer) reset() string {
	s := l.val.String()
	l.val.Reset()
	l.width = 0
}

// lex creates a new scanner for the input string.
func lex(input reader) *lexer {
	return &lexer{input: input}
}

// nextToken returns the next token from the input.
func (l *lexer) nextToken() token {
	if l.done != nil {
		// only happens after itemEOF, itemError, or itemUnexpectedRune
		return *l.done
	}
	token := l.lexMain()
	l.reset()
	if token == tokenEOF || token.typ == itemError || token.typ == itemUnexpectedRune {
		 l.done = &token
	}
  return token
}

// peekToken checks if the next token in the input is t. This can discard
// whitespace, and it only behaves nicely for punctuation since the input
// stream can only back up one rune.
func (l *lexer) peek(t rune) bool {
	for {
		switch r := l.next(); {
		case unicode.IsSpace(r):
			l.reset()
		default:
			l.backup()
			return r == t
		}
	}
}

