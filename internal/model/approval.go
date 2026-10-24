package model

import (
	"encoding/json"
	"fmt"
	"time"
)

// ApprovalSchemaV1 is the only accepted approval schema.
const ApprovalSchemaV1 = "kodis.approval/v1"

// MaxApprovalTTL bounds how long an approval stays valid.
const MaxApprovalTTL = time.Hour

// MaxApprovalBytes bounds the size of an encoded approval.
const MaxApprovalBytes = 64 << 10

const approvalSignDomain = "kodis.approval/v1\x00"

// ApprovalStatement is what a human approver signs: one exact plan hash,
// who approved it, with which key, and for how long.
//
// Field order is part of the signed encoding; changing it invalidates
// every existing signature and must bump ApprovalSchemaV1.
type ApprovalStatement struct {
	Schema     string    `json:"schema"`
	PlanHash   Digest    `json:"planHash"`
	ApproverID string    `json:"approverId"`
	KeyID      string    `json:"keyId"`
	IssuedAt   time.Time `json:"issuedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// Approval is a signed statement. Signature is checked by
// internal/approve, not here.
type Approval struct {
	Statement ApprovalStatement `json:"statement"`
	Signature []byte            `json:"signature"`
}

// MarshalText encodes the digest in the form produced by String.
func (d Digest) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

// UnmarshalText accepts only the form produced by String.
func (d *Digest) UnmarshalText(b []byte) error {
	v, err := ParseDigest(string(b))
	if err != nil {
		return err
	}
	*d = v
	return nil
}

// Validate checks the statement's structure and validity window.
func (s ApprovalStatement) Validate() error {
	if s.Schema != ApprovalSchemaV1 {
		return &Error{Code: CodeUnsupportedSchema, Field: "schema", Msg: fmt.Sprintf("want %q, got %q", ApprovalSchemaV1, s.Schema)}
	}
	if s.PlanHash == (Digest{}) {
		return invalid("planHash", "must be set")
	}
	if err := checkToken("approverId", s.ApproverID); err != nil {
		return err
	}
	if err := checkToken("keyId", s.KeyID); err != nil {
		return err
	}
	for name, t := range map[string]time.Time{"issuedAt": s.IssuedAt, "expiresAt": s.ExpiresAt} {
		if t.IsZero() {
			return invalid(name, "must be set")
		}
		if t.Location() != time.UTC {
			return invalid(name, "must be UTC")
		}
	}
	if !s.ExpiresAt.After(s.IssuedAt) {
		return invalid("expiresAt", "must be after issuedAt")
	}
	if s.ExpiresAt.Sub(s.IssuedAt) > MaxApprovalTTL {
		return invalid("expiresAt", "validity window exceeds %s", MaxApprovalTTL)
	}
	return nil
}

// SignedBytes returns the exact bytes an approver signs.
func (s ApprovalStatement) SignedBytes() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, &Error{Code: CodeMalformed, Msg: err.Error()}
	}
	return append([]byte(approvalSignDomain), b...), nil
}

// Validate checks structure only; it does not verify the signature.
func (a Approval) Validate() error {
	if err := a.Statement.Validate(); err != nil {
		return err
	}
	if len(a.Signature) == 0 {
		return invalid("signature", "must be set")
	}
	return nil
}

// DecodeApproval strictly decodes and structurally validates an approval.
func DecodeApproval(data []byte) (Approval, error) {
	var a Approval
	if err := DecodeStrict(data, MaxApprovalBytes, &a); err != nil {
		return Approval{}, err
	}
	if err := a.Validate(); err != nil {
		return Approval{}, err
	}
	return a, nil
}
