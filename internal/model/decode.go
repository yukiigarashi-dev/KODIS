package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// MaxPlanBytes bounds the size of an encoded plan.
const MaxPlanBytes = 1 << 20

const maxDepth = 16

// DecodePlan parses and validates an untrusted encoded plan.
func DecodePlan(data []byte) (Plan, error) {
	var p Plan
	if err := DecodeStrict(data, MaxPlanBytes, &p); err != nil {
		return Plan{}, err
	}
	if err := p.Validate(); err != nil {
		return Plan{}, err
	}
	return p, nil
}

// DecodeStrict decodes a single JSON object into v. It rejects input
// larger than maxBytes, duplicate object keys (including keys that
// encoding/json would treat as equal under case folding), unknown fields
// and trailing data. It does not validate the result.
func DecodeStrict(data []byte, maxBytes int, v any) error {
	if len(data) > maxBytes {
		return &Error{Code: CodeTooLarge, Msg: fmt.Sprintf("%d bytes exceeds %d", len(data), maxBytes)}
	}
	if err := checkStructure(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return &Error{Code: CodeMalformed, Msg: err.Error()}
	}
	return nil
}

// checkStructure walks the token stream: the top level must be a single
// object, nesting is bounded and no object repeats a key.
func checkStructure(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return &Error{Code: CodeMalformed, Msg: err.Error()}
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return &Error{Code: CodeMalformed, Msg: "top level must be an object"}
	}
	if err := walkObject(dec, "$", 1); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return &Error{Code: CodeTrailingData, Msg: "unexpected data after top-level object"}
	}
	return nil
}

func walkValue(dec *json.Decoder, path string, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return &Error{Code: CodeMalformed, Field: path, Msg: err.Error()}
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= maxDepth {
		return &Error{Code: CodeMalformed, Field: path, Msg: "nesting too deep"}
	}
	if d == '{' {
		return walkObject(dec, path, depth+1)
	}
	for i := 0; dec.More(); i++ {
		if err := walkValue(dec, fmt.Sprintf("%s[%d]", path, i), depth+1); err != nil {
			return err
		}
	}
	return closing(dec, path)
}

func walkObject(dec *json.Decoder, path string, depth int) error {
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return &Error{Code: CodeMalformed, Field: path, Msg: err.Error()}
		}
		key, ok := tok.(string)
		if !ok {
			return &Error{Code: CodeMalformed, Field: path, Msg: "object key is not a string"}
		}
		k := foldKey(key)
		if seen[k] {
			return &Error{Code: CodeDuplicateKey, Field: path + "." + key, Msg: "duplicate object key"}
		}
		seen[k] = true
		if err := walkValue(dec, path+"."+key, depth); err != nil {
			return err
		}
	}
	return closing(dec, path)
}

func closing(dec *json.Decoder, path string) error {
	if _, err := dec.Token(); err != nil {
		return &Error{Code: CodeMalformed, Field: path, Msg: err.Error()}
	}
	return nil
}

// foldKey mirrors the case folding encoding/json uses to match object keys
// to struct fields, so that e.g. "id" and "ID" count as the same key.
func foldKey(s string) string {
	return strings.Map(func(r rune) rune { return unicode.ToUpper(unicode.ToLower(r)) }, s)
}
