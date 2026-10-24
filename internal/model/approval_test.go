package model

import (
	"strings"
	"testing"
	"time"
)

func validStatement(t *testing.T) ApprovalStatement {
	t.Helper()
	return ApprovalStatement{
		Schema:     ApprovalSchemaV1,
		PlanHash:   mustHash(t, validPlan()),
		ApproverID: "alice",
		KeyID:      "ed25519-abc",
		IssuedAt:   time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC),
		ExpiresAt:  time.Date(2026, 10, 25, 9, 15, 0, 0, time.UTC),
	}
}

func TestApprovalStatementValidate(t *testing.T) {
	if err := validStatement(t).Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*ApprovalStatement){
		"wrong schema":      func(s *ApprovalStatement) { s.Schema = ApprovalSchemaV1 + "x" },
		"zero plan hash":    func(s *ApprovalStatement) { s.PlanHash = Digest{} },
		"empty approver":    func(s *ApprovalStatement) { s.ApproverID = "" },
		"approver w/ space": func(s *ApprovalStatement) { s.ApproverID = "a b" },
		"empty key id":      func(s *ApprovalStatement) { s.KeyID = "" },
		"zero issued":       func(s *ApprovalStatement) { s.IssuedAt = time.Time{} },
		"zero expires":      func(s *ApprovalStatement) { s.ExpiresAt = time.Time{} },
		"non-UTC issued":    func(s *ApprovalStatement) { s.IssuedAt = s.IssuedAt.In(time.FixedZone("X", 3600)) },
		"non-UTC expires":   func(s *ApprovalStatement) { s.ExpiresAt = s.ExpiresAt.In(time.FixedZone("X", 3600)) },
		"expires == issued": func(s *ApprovalStatement) { s.ExpiresAt = s.IssuedAt },
		"expires < issued":  func(s *ApprovalStatement) { s.ExpiresAt = s.IssuedAt.Add(-time.Second) },
		"window too long":   func(s *ApprovalStatement) { s.ExpiresAt = s.IssuedAt.Add(MaxApprovalTTL + time.Nanosecond) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := validStatement(t)
			mutate(&s)
			if err := s.Validate(); err == nil {
				t.Fatal("expected rejection")
			}
			if _, err := s.SignedBytes(); err == nil {
				t.Fatal("invalid statement produced signed bytes")
			}
		})
	}
}

func TestSignedBytesGolden(t *testing.T) {
	b, err := validStatement(t).SignedBytes()
	if err != nil {
		t.Fatal(err)
	}
	want := "kodis.approval/v1\x00" +
		`{"schema":"kodis.approval/v1","planHash":"sha256:52b2c052132234e8d039b93e5337ba594f9af88563abf343aab940fbdebf817b",` +
		`"approverId":"alice","keyId":"ed25519-abc","issuedAt":"2026-10-25T09:00:00Z","expiresAt":"2026-10-25T09:15:00Z"}`
	if string(b) != want {
		t.Fatalf("signed encoding changed:\n got %q\nwant %q", b, want)
	}
}

func TestDecodeApproval(t *testing.T) {
	good := `{"statement":{"schema":"kodis.approval/v1","planHash":"sha256:52b2c052132234e8d039b93e5337ba594f9af88563abf343aab940fbdebf817b",` +
		`"approverId":"alice","keyId":"ed25519-abc","issuedAt":"2026-10-25T09:00:00Z","expiresAt":"2026-10-25T09:15:00Z"},"signature":"AAAA"}`
	if _, err := DecodeApproval([]byte(good)); err != nil {
		t.Fatal(err)
	}
	cases := map[string][2]string{
		"uppercase hash":  {"sha256:52b2", "sha256:52B2"},
		"no hash prefix":  {"sha256:52b2", "52b2"},
		"empty signature": {`"signature":"AAAA"`, `"signature":""`},
		"null signature":  {`"signature":"AAAA"`, `"signature":null`},
		"bad base64":      {`"signature":"AAAA"`, `"signature":"!!!"`},
		"unknown field":   {`"signature"`, `"approved":true,"signature"`},
		"duplicate key":   {`"approverId":"alice"`, `"approverId":"alice","approverID":"bob"`},
		"non-UTC time":    {`"issuedAt":"2026-10-25T09:00:00Z"`, `"issuedAt":"2026-10-25T18:00:00+09:00"`},
		"window too long": {`"expiresAt":"2026-10-25T09:15:00Z"`, `"expiresAt":"2026-10-25T10:15:00Z"`},
		"trailing":        {`"signature":"AAAA"}`, `"signature":"AAAA"}{}`},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(good, r[0]) {
				t.Fatalf("fixture lacks %q", r[0])
			}
			if _, err := DecodeApproval([]byte(strings.Replace(good, r[0], r[1], 1))); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}
