package model

import "fmt"

// Code is a machine-readable rejection reason.
type Code string

const (
	CodeTooLarge          Code = "too_large"
	CodeMalformed         Code = "malformed"
	CodeDuplicateKey      Code = "duplicate_key"
	CodeTrailingData      Code = "trailing_data"
	CodeUnsupportedSchema Code = "unsupported_schema"
	CodeInvalidField      Code = "invalid_field"
)

// Error is returned for every rejected input. Callers must treat any error
// as a rejection; there is no partially valid result.
type Error struct {
	Code  Code
	Field string
	Msg   string
}

func (e *Error) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Msg)
	}
	return fmt.Sprintf("%s: %s: %s", e.Code, e.Field, e.Msg)
}

func invalid(field, format string, args ...any) *Error {
	return &Error{Code: CodeInvalidField, Field: field, Msg: fmt.Sprintf(format, args...)}
}
