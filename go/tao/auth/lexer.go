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

// This code borrows from the lexer design and implementation described
// by Rob Pike, "Lexical Scanning in Go", GTUG Sydney, Aug 30, 2011.
// See: http://cuddle.googlecode.com/hg/talk/lex.html#slide-40
//
// It also borrows from the lexer in package
// github.com/kevinawalsh/datalog/dlengine.

package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"unicode"
	"unicode/utf8"
)

// token is a value returned from the lexer.
type token struct {
	typ itemType
	val interface{} // string, int64, error, or nil
}

// itemType identifies the type of lex items.
type itemType int

const (
	itemError          itemType = iota // value contains error
	itemUnexpectedRune                 // value contains the rune
	itemEOF                            // value is nil
	itemKeyword                        // value contains the keyword
	itemIdentifier                     // value contains the identifer
	itemStr                            // value contains the string
	itemBytes                          // value contains the []byte slice
	itemInt                            // value contains the int64
	itemLP                             // value contains '('
	itemRP                             // value contains ')'
	itemComma                          // value contains ','
	itemDot                            // value contains '.'
	itemColon                          // value contains ':'
	itemWhitespace                     // value contains ' ', '\t', '\n', etc.
)

var (
	tokenFrom      = token{itemKeyword, "from"}
	tokenUntil     = token{itemKeyword, "until"}
	tokenSays      = token{itemKeyword, "says"}
	tokenSpeaksfor = token{itemKeyword, "speaksfor"}
	tokenForall    = token{itemKeyword, "forall"}
	tokenExists    = token{itemKeyword, "exists"}
	tokenImplies   = token{itemKeyword, "implies"}
	tokenOr        = token{itemKeyword, "or"}
	tokenAnd       = token{itemKeyword, "and"}
	tokenNot       = token{itemKeyword, "not"}
	tokenFalse     = token{itemKeyword, "false"}
	tokenTrue      = token{itemKeyword, "true"}
	tokenExt       = token{itemKeyword, "ext"}
	tokenLP        = token{itemLP, '('}
	tokenRP        = token{itemRP, ')'}
	tokenComma     = token{itemComma, ','}
	tokenDot       = token{itemDot, '.'}
	tokenColon     = token{itemColon, ':'}
	tokenEOF       = token{itemEOF, nil}
)

var prinTokens = map[token]bool{
	token{itemKeyword, "tpm"}: true,
	token{itemKeyword, "key"}: true,
}

func isPrinToken(i token) bool {
	_, ok := prinTokens[i]
	return ok
}

func AddPrinTokens(keywords ...string) {
	for _, keyword := range keywords {
		prinTokens[token{itemKeyword, keyword}] = true
	}
}

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
	case itemStr:
		return fmt.Sprintf("Str{%q}", i.val)
	case itemBytes:
		return fmt.Sprintf("Bytes{%02x}", i.val)
	case itemInt:
		return fmt.Sprintf("Int{%v}", i.val)
	case itemLP, itemRP, itemComma, itemDot, itemColon:
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
			return tokenLP
		case r == ')':
			return tokenRP
		case r == ',':
			return tokenComma
		case r == '.':
			return tokenDot
		case r == ':':
			return tokenColon
		case r == '"':
			l.backup()
			return l.lexStr()
		case r == '[' || r == '{':
			l.backup()
			return l.lexBytes()
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

func (l *lexer) lexStr() token {
	var s string
	if _, err := fmt.Fscanf(l.input, "%q", &s); err != nil {
		return token{itemError, err}
	}
	return token{itemStr, s}
}

func (l *lexer) lexBytes() token {
	r := l.next()
	if r == '[' {
		var b []byte
		s := ""
		for {
			r = l.next()
			switch {
			case hexChar(r):
				s += string(r)
			case unicode.IsSpace(r) || r == ']':
				x, err := hex.DecodeString(s)
				if err != nil {
					return token{itemError, err}
				}
				b = append(b, x...)
				if r == ']' {
					return token{itemBytes, b}
				}
			default:
				return token{itemError, fmt.Errorf("expected bytes, found %q", s)}
			}
		}
	} else if r == '{' {
		s := ""
		for {
			r = l.next()
			switch {
			case lower(r) || upper(r) || digit(r) || r == '_' || r == '-' || r == '=' || r == '\r' || r == '\n':
				s += string(r)
			case r == '}':
				b, err := base64.URLEncoding.DecodeString(s)
				if err != nil {
					return token{itemError, err}
				}
				return token{itemBytes, b}
			default:
				return token{itemError, fmt.Errorf("expected base64w, found %q", s)}
			}
		}
	} else {
		return token{itemError, fmt.Errorf("expected '[' or '{', found %q", r)}
	}
}

func (l *lexer) lexInt() token {
	var i int64
	if _, err := fmt.Fscanf(l.input, "%d", &i); err != nil {
		return token{itemError, err}
	}
	return token{itemInt, i}
}

func (l *lexer) lexKeyword() token {
	for {
		r := l.next()
		if !lower(r) {
			l.backup()
			t := token{itemKeyword, l.reset()}
			return t
		}
	}
}

func (l *lexer) lexIdentifier() token {
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
	return '0' <= r && r <= '9'
}

func lower(r rune) bool {
	return 'a' <= r && r <= 'z'
}

func upper(r rune) bool {
	return 'A' <= r && r <= 'Z'
}

func hexChar(r rune) bool {
	return ('0' <= r && r <= '9') || ('a' <= r && r <= 'f') || ('A' <= r && r <= 'F')
}

// next returns the next rune in the input.
func (l *lexer) next() (r rune) {
	r, n, err := l.input.ReadRune()
	if err == io.EOF {
		l.width = 0
		return eof
	}
	l.val.WriteRune(r)
	// BUG(kwalsh) fmt.ScanState.ReadRune() returns incorrect length. See issue
	// 8512 here: https://code.google.com/p/go/issues/detail?id=8512
	n = utf8.RuneLen(r)
	l.width = n
	return r
}

// backup steps back one rune. Can be called only once per call of next.
func (l *lexer) backup() {
	if l.width > 0 {
		l.input.UnreadRune()
		l.val.Truncate(l.val.Len() - l.width)
		l.width = 0
	}
}

// reset consumes accumulated input and resets val and width.
func (l *lexer) reset() string {
	s := l.val.String()
	l.val.Reset()
	l.width = 0
	return s
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

// peek gets the next rune in the input without advancing the input.
func (l *lexer) peek() rune {
	r := l.next()
	l.backup()
	return r
}
