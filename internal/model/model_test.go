package model

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func validPlan() Plan {
	return Plan{
		Schema:     PlanSchemaV1,
		ID:         "plan-0001",
		TenantID:   "tenant-contoso.example.test",
		CreatedAt:  time.Date(2026, 10, 24, 1, 2, 3, 0, time.UTC),
		FindingIDs: []string{"finding-0001", "finding-0002"},
		Actions: []Action{{
			ID:              "action-0001",
			Operation:       OpSetConditionalAccessState,
			Target:          ResourceRef{Kind: KindConditionalAccessPolicy, ID: "ca-require-mfa-admins"},
			ExpectedVersion: "v7",
			ExpectedState:   "disabled",
			DesiredState:    "enabledForReportingButNotEnforced",
		}},
	}
}

const validPlanJSON = `{
  "schema": "kodis.plan/v1",
  "id": "plan-0001",
  "tenantId": "tenant-contoso.example.test",
  "createdAt": "2026-10-24T01:02:03Z",
  "findingIds": ["finding-0001", "finding-0002"],
  "actions": [{
    "id": "action-0001",
    "operation": "conditionalAccess.setState",
    "target": {"kind": "conditionalAccessPolicy", "id": "ca-require-mfa-admins"},
    "expectedVersion": "v7",
    "expectedState": "disabled",
    "desiredState": "enabledForReportingButNotEnforced"
  }]
}`

func wantCode(t *testing.T, err error, code Code) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("got error %v (%T), want *model.Error with code %s", err, err, code)
	}
	if e.Code != code {
		t.Fatalf("got code %s (%v), want %s", e.Code, err, code)
	}
}

func TestValidPlan(t *testing.T) {
	if err := validPlan().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*Plan){
		"wrong schema":         func(p *Plan) { p.Schema = "kodis.plan/v2" },
		"empty schema":         func(p *Plan) { p.Schema = "" },
		"empty id":             func(p *Plan) { p.ID = "" },
		"id with space":        func(p *Plan) { p.ID = "plan 1" },
		"id with slash":        func(p *Plan) { p.ID = "plan/1" },
		"id non-ascii":         func(p *Plan) { p.ID = "plаn" }, // Cyrillic a
		"id too long":          func(p *Plan) { p.ID = strings.Repeat("a", maxTokenLen+1) },
		"empty tenant":         func(p *Plan) { p.TenantID = "" },
		"zero time":            func(p *Plan) { p.CreatedAt = time.Time{} },
		"non-UTC time":         func(p *Plan) { p.CreatedAt = p.CreatedAt.In(time.FixedZone("JST", 9*3600)) },
		"local time":           func(p *Plan) { p.CreatedAt = p.CreatedAt.In(time.Local) },
		"nil findings":         func(p *Plan) { p.FindingIDs = nil },
		"empty findings":       func(p *Plan) { p.FindingIDs = []string{} },
		"unsorted findings":    func(p *Plan) { p.FindingIDs = []string{"b", "a"} },
		"duplicate findings":   func(p *Plan) { p.FindingIDs = []string{"a", "a"} },
		"bad finding id":       func(p *Plan) { p.FindingIDs = []string{""} },
		"nil actions":          func(p *Plan) { p.Actions = nil },
		"empty actions":        func(p *Plan) { p.Actions = []Action{} },
		"too many actions":     func(p *Plan) { p.Actions = manyActions(MaxActions + 1) },
		"duplicate action id":  func(p *Plan) { p.Actions = append(p.Actions, p.Actions[0]) },
		"empty action id":      func(p *Plan) { p.Actions[0].ID = "" },
		"unknown operation":    func(p *Plan) { p.Actions[0].Operation = "conditionalAccess.delete" },
		"empty operation":      func(p *Plan) { p.Actions[0].Operation = "" },
		"operation wrong case": func(p *Plan) { p.Actions[0].Operation = "ConditionalAccess.SetState" },
		"unknown kind":         func(p *Plan) { p.Actions[0].Target.Kind = "user" },
		"empty target id":      func(p *Plan) { p.Actions[0].Target.ID = "" },
		"empty version":        func(p *Plan) { p.Actions[0].ExpectedVersion = "" },
		"quoted version":       func(p *Plan) { p.Actions[0].ExpectedVersion = `W/"7"` },
		"empty expected state": func(p *Plan) { p.Actions[0].ExpectedState = "" },
		"empty desired state":  func(p *Plan) { p.Actions[0].DesiredState = "" },
		"no-op action":         func(p *Plan) { p.Actions[0].DesiredState = p.Actions[0].ExpectedState },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := validPlan()
			mutate(&p)
			if err := p.Validate(); err == nil {
				t.Fatal("expected rejection")
			} else {
				var e *Error
				if !errors.As(err, &e) {
					t.Fatalf("untyped error %v", err)
				}
			}
			if _, err := HashPlan(p); err == nil {
				t.Fatal("invalid plan must not have a hash")
			}
		})
	}
}

func TestMaxActionsAccepted(t *testing.T) {
	p := validPlan()
	p.Actions = manyActions(MaxActions)
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

func manyActions(n int) []Action {
	base := validPlan().Actions[0]
	out := make([]Action, n)
	for i := range out {
		out[i] = base
		out[i].ID = base.ID + "-" + strings.Repeat("x", i+1)
	}
	return out
}

func TestFindingValidate(t *testing.T) {
	ok := Finding{
		ID:       "finding-0001",
		RuleID:   "ca.admin-mfa-disabled",
		Severity: SeverityHigh,
		Resource: ResourceRef{Kind: KindConditionalAccessPolicy, ID: "ca-require-mfa-admins"},
		Summary:  "MFA policy for administrators is disabled",
	}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Finding){
		"empty id":         func(f *Finding) { f.ID = "" },
		"empty rule":       func(f *Finding) { f.RuleID = "" },
		"unknown severity": func(f *Finding) { f.Severity = "urgent" },
		"empty severity":   func(f *Finding) { f.Severity = "" },
		"unknown kind":     func(f *Finding) { f.Resource.Kind = "group" },
		"empty summary":    func(f *Finding) { f.Summary = "" },
		"long summary":     func(f *Finding) { f.Summary = strings.Repeat("a", maxSummaryLen+1) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := ok
			mutate(&f)
			if err := f.Validate(); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestDecodePlanValid(t *testing.T) {
	p, err := DecodePlan([]byte(validPlanJSON))
	if err != nil {
		t.Fatal(err)
	}
	if p.CreatedAt.Location() != time.UTC {
		t.Fatalf("decoded time not UTC: %v", p.CreatedAt.Location())
	}
	if got, want := mustHash(t, p), mustHash(t, validPlan()); got != want {
		t.Fatalf("decoded plan hash %s != constructed plan hash %s", got, want)
	}
}

func TestDecodePlanRejects(t *testing.T) {
	replace := func(old, new string) string {
		if !strings.Contains(validPlanJSON, old) {
			t.Fatalf("fixture does not contain %q", old)
		}
		return strings.Replace(validPlanJSON, old, new, 1)
	}
	cases := []struct {
		name string
		in   string
		code Code
	}{
		{"empty", ``, CodeMalformed},
		{"whitespace", "  \n", CodeMalformed},
		{"null", `null`, CodeMalformed},
		{"array", `[` + validPlanJSON + `]`, CodeMalformed},
		{"string", `"plan"`, CodeMalformed},
		{"truncated", validPlanJSON[:len(validPlanJSON)-1], CodeMalformed},
		{"syntax error", replace(`"id": "plan-0001",`, `"id": "plan-0001",,`), CodeMalformed},
		{"unknown field", replace(`"id": "plan-0001",`, `"id": "plan-0001", "approved": true,`), CodeMalformed},
		{"unknown nested field", replace(`"expectedVersion": "v7",`, `"expectedVersion": "v7", "force": true,`), CodeMalformed},
		{"wrong type", replace(`"id": "plan-0001"`, `"id": 1`), CodeMalformed},
		{"bad time", replace(`2026-10-24T01:02:03Z`, `yesterday`), CodeMalformed},
		{"non-UTC time", replace(`2026-10-24T01:02:03Z`, `2026-10-24T10:02:03+09:00`), CodeInvalidField},
		{"null findings", replace(`"findingIds": ["finding-0001", "finding-0002"]`, `"findingIds": null`), CodeInvalidField},
		{"empty findings", replace(`"findingIds": ["finding-0001", "finding-0002"]`, `"findingIds": []`), CodeInvalidField},
		{"offset zero not Z", replace(`2026-10-24T01:02:03Z`, `2026-10-24T01:02:03+00:00`), CodeInvalidField},
		{"null field", replace(`"id": "plan-0001"`, `"id": null`), CodeInvalidField},
		{"duplicate key", replace(`"id": "plan-0001",`, `"id": "plan-0001", "id": "plan-0002",`), CodeDuplicateKey},
		{"duplicate key case-folded", replace(`"id": "plan-0001",`, `"id": "plan-0001", "ID": "plan-0002",`), CodeDuplicateKey},
		{"duplicate key long-s fold", replace(`"schema": "kodis.plan/v1",`, `"schema": "kodis.plan/v1", "ſchema": "kodis.plan/v1",`), CodeDuplicateKey},
		{"duplicate key escaped", replace(`"id": "plan-0001",`, `"id": "plan-0001", "id": "plan-0002",`), CodeDuplicateKey},
		{"duplicate nested key", replace(`"desiredState": "enabledForReportingButNotEnforced"`, `"desiredState": "enabledForReportingButNotEnforced", "desiredState": "enabled"`), CodeDuplicateKey},
		{"trailing object", validPlanJSON + `{}`, CodeTrailingData},
		{"trailing garbage", validPlanJSON + `x`, CodeTrailingData},
		{"two plans", validPlanJSON + validPlanJSON, CodeTrailingData},
		{"too deep", replace(`"id": "plan-0001",`, `"id": "plan-0001", "x": `+strings.Repeat("[", maxDepth+1)+strings.Repeat("]", maxDepth+1)+`,`), CodeMalformed},
		{"too large", validPlanJSON + strings.Repeat(" ", MaxPlanBytes), CodeTooLarge},
		{"wrong schema", replace(`kodis.plan/v1`, `kodis.plan/v0`), CodeUnsupportedSchema},
		{"no-op action", replace(`"expectedState": "disabled"`, `"expectedState": "enabledForReportingButNotEnforced"`), CodeInvalidField},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := DecodePlan([]byte(c.in))
			wantCode(t, err, c.code)
		})
	}
}

func TestHashStableAcrossEncodings(t *testing.T) {
	want := mustHash(t, validPlan())
	compact, err := json.Marshal(validPlan())
	if err != nil {
		t.Fatal(err)
	}
	reordered := `{"actions":[{"desiredState":"enabledForReportingButNotEnforced","expectedState":"disabled","expectedVersion":"v7",` +
		`"target":{"id":"ca-require-mfa-admins","kind":"conditionalAccessPolicy"},"operation":"conditionalAccess.setState","id":"action-0001"}],` +
		`"findingIds":["finding-0001","finding-0002"],"createdAt":"2026-10-24T01:02:03.000Z","tenantId":"tenant-contoso.example.test","id":"plan-0001","schema":"kodis.plan/v1"}`
	for name, in := range map[string]string{"pretty": validPlanJSON, "compact": string(compact), "reordered": reordered} {
		p, err := DecodePlan([]byte(in))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := mustHash(t, p); got != want {
			t.Errorf("%s: hash %s, want %s", name, got, want)
		}
	}
}

func TestHashChangesWithEveryField(t *testing.T) {
	base := mustHash(t, validPlan())
	mutations := map[string]func(*Plan){
		"id":              func(p *Plan) { p.ID = "plan-0002" },
		"tenant":          func(p *Plan) { p.TenantID = "tenant-other.example.test" },
		"createdAt":       func(p *Plan) { p.CreatedAt = p.CreatedAt.Add(time.Nanosecond) },
		"findingIds":      func(p *Plan) { p.FindingIDs = []string{"finding-0001"} },
		"action id":       func(p *Plan) { p.Actions[0].ID = "action-0002" },
		"target id":       func(p *Plan) { p.Actions[0].Target.ID = "ca-other" },
		"expectedVersion": func(p *Plan) { p.Actions[0].ExpectedVersion = "v8" },
		"expectedState":   func(p *Plan) { p.Actions[0].ExpectedState = "enabled" },
		"desiredState":    func(p *Plan) { p.Actions[0].DesiredState = "enabled" },
		"action order": func(p *Plan) {
			b := p.Actions[0]
			b.ID = "action-0000"
			p.Actions = append([]Action{b}, p.Actions...)
		},
	}
	seen := map[Digest]string{base: "base"}
	for name, mutate := range mutations {
		p := validPlan()
		mutate(&p)
		d := mustHash(t, p)
		if prev, dup := seen[d]; dup {
			t.Errorf("%s: hash collides with %s", name, prev)
		}
		seen[d] = name
	}
}

// TestHashGolden pins the canonical encoding. If this fails, the plan
// encoding changed: every existing approval is invalidated and the schema
// version must be bumped.
func TestHashGolden(t *testing.T) {
	const wantCanonical = `{"schema":"kodis.plan/v1","id":"plan-0001","tenantId":"tenant-contoso.example.test","createdAt":"2026-10-24T01:02:03Z",` +
		`"findingIds":["finding-0001","finding-0002"],"actions":[{"id":"action-0001","operation":"conditionalAccess.setState",` +
		`"target":{"kind":"conditionalAccessPolicy","id":"ca-require-mfa-admins"},"expectedVersion":"v7","expectedState":"disabled",` +
		`"desiredState":"enabledForReportingButNotEnforced"}]}`
	b, err := CanonicalPlan(validPlan())
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != wantCanonical {
		t.Fatalf("canonical encoding changed:\n got %s\nwant %s", b, wantCanonical)
	}
	// Computed independently: sha256("kodis.plan/v1\x00" + wantCanonical).
	const want = "sha256:52b2c052132234e8d039b93e5337ba594f9af88563abf343aab940fbdebf817b"
	if got := mustHash(t, validPlan()).String(); got != want {
		t.Fatalf("plan hash changed:\n got %s\nwant %s", got, want)
	}
}

func TestDigestRoundTrip(t *testing.T) {
	d := mustHash(t, validPlan())
	got, err := ParseDigest(d.String())
	if err != nil {
		t.Fatal(err)
	}
	if got != d {
		t.Fatal("round trip mismatch")
	}
	hexPart := strings.TrimPrefix(d.String(), digestPrefix)
	for name, s := range map[string]string{
		"empty":      "",
		"no prefix":  hexPart,
		"sha512":     "sha512:" + hexPart,
		"uppercase":  digestPrefix + strings.ToUpper(hexPart),
		"short":      d.String()[:len(d.String())-2],
		"long":       d.String() + "00",
		"non-hex":    digestPrefix + strings.Repeat("g", 64),
		"whitespace": " " + d.String(),
	} {
		if _, err := ParseDigest(s); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func mustHash(t *testing.T, p Plan) Digest {
	t.Helper()
	d, err := HashPlan(p)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// FuzzDecodePlan checks that any accepted input is valid, hashable, and
// survives a re-encode with the same hash.
func FuzzDecodePlan(f *testing.F) {
	f.Add([]byte(validPlanJSON))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"id":"a","ID":"b"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := DecodePlan(data)
		if err != nil {
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("untyped error: %v", err)
			}
			return
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("accepted invalid plan: %v", err)
		}
		d1, err := HashPlan(p)
		if err != nil {
			t.Fatalf("accepted plan has no hash: %v", err)
		}
		b, err := CanonicalPlan(p)
		if err != nil {
			t.Fatal(err)
		}
		p2, err := DecodePlan(b)
		if err != nil {
			t.Fatalf("canonical form rejected: %v", err)
		}
		if d2 := mustHash(t, p2); d1 != d2 {
			t.Fatalf("hash not stable across re-encode: %s != %s", d1, d2)
		}
	})
}
