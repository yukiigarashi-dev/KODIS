// Package archtest enforces KODIS package boundaries and the stdlib-only
// dependency rule. The checks are pure functions over package metadata so
// that they can be tested against synthetic violations.
package archtest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
)

// Package is the subset of `go list -json` output used by the checks.
type Package struct {
	ImportPath   string
	Dir          string
	Standard     bool
	GoFiles      []string
	Imports      []string
	Deps         []string
	TestImports  []string
	XTestImports []string
}

// Rule forbids a module package (and its subpackages) from depending on the
// listed paths. Module-relative paths (starting with "internal/" or "cmd/")
// are checked against transitive deps; stdlib paths are checked against
// direct imports only, because common stdlib packages pull in os etc.
type Rule struct {
	Pkg       string
	Forbidden []string
	Reason    string
}

// Rules are the trust boundaries from CLAUDE.md. Loosening them requires
// explicit human approval.
var Rules = []Rule{
	{
		Pkg:       "internal/execute",
		Forbidden: []string{"internal/plan", "internal/evaluate", "internal/inspect", "internal/mockentra"},
		Reason:    "executor must only consume model.Plan and model.Approval",
	},
	{
		Pkg:       "internal/policy",
		Forbidden: []string{"internal/execute", "internal/mockentra", "internal/inspect", "internal/verify", "internal/entra", "os", "os/exec", "net", "net/http", "io/fs", "syscall"},
		Reason:    "policy engine must be pure and free of I/O",
	},
	{
		Pkg:       "internal/verify",
		Forbidden: []string{"internal/execute"},
		Reason:    "verification must not rely on executor results",
	},
	{
		Pkg:       "internal/plan",
		Forbidden: []string{"internal/execute", "internal/approve"},
		Reason:    "plans are untrusted proposals and cannot execute or approve",
	},
	{
		Pkg:       "internal/approve",
		Forbidden: []string{"internal/execute", "internal/plan", "internal/evaluate", "internal/inspect", "internal/entra", "internal/policy", "net", "net/http", "os/exec"},
		Reason:    "approval only signs and verifies plan hashes; it must not reach tenant state or networks",
	},
	{
		Pkg:       "internal/evaluate",
		Forbidden: []string{"internal/execute"},
		Reason:    "evaluation is read-only",
	},
	{
		Pkg:       "internal/inspect",
		Forbidden: []string{"internal/execute"},
		Reason:    "inspection is read-only",
	},
}

// ImportRule restricts which module packages may depend on Pkg. Packages
// not listed are denied, so new packages are covered automatically.
type ImportRule struct {
	Pkg              string
	AllowedImporters []string
	Reason           string
}

// ImportRules restrict access to packages that grant write capability.
var ImportRules = []ImportRule{
	{
		Pkg:              "internal/mockentra",
		AllowedImporters: []string{"cmd/kodis"},
		Reason:           "the mock tenant exposes write access without entra.Writer and may only be wired in by the CLI",
	},
}

// CheckImporters reports non-test packages that depend, directly or
// transitively, on a restricted package without being allowed to.
func CheckImporters(module string, pkgs []Package, rules []ImportRule) []string {
	var out []string
	for _, p := range pkgs {
		if p.Standard || !within(p.ImportPath, module) {
			continue
		}
		for _, r := range rules {
			target := module + "/" + r.Pkg
			if within(p.ImportPath, target) {
				continue
			}
			allowed := false
			for _, a := range r.AllowedImporters {
				if within(p.ImportPath, module+"/"+a) {
					allowed = true
				}
			}
			if allowed {
				continue
			}
			for _, d := range p.Deps {
				if within(d, target) {
					out = append(out, fmt.Sprintf("%s depends on %s: %s", p.ImportPath, d, r.Reason))
					break
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// WriterPkg is the package declaring the Writer interface.
const WriterPkg = "internal/entra"

// WriterAllowed lists the packages whose non-test files may reference
// entra.Writer.
var WriterAllowed = []string{"internal/execute", "internal/mockentra"}

func within(path, base string) bool {
	return path == base || strings.HasPrefix(path, base+"/")
}

func isModuleRel(p string) bool {
	return strings.HasPrefix(p, "internal/") || strings.HasPrefix(p, "cmd/")
}

// CheckBoundaries returns one message per rule violation.
func CheckBoundaries(module string, pkgs []Package, rules []Rule) []string {
	var out []string
	for _, p := range pkgs {
		for _, r := range rules {
			if !within(p.ImportPath, module+"/"+r.Pkg) {
				continue
			}
			// Report each offending dependency once per rule, even if it
			// matches several forbidden prefixes (e.g. "net" and "net/http").
			bad := map[string]bool{}
			for _, f := range r.Forbidden {
				target, deps := f, p.Imports
				if isModuleRel(f) {
					target, deps = module+"/"+f, p.Deps
				}
				for _, d := range deps {
					if within(d, target) {
						bad[d] = true
					}
				}
			}
			for d := range bad {
				out = append(out, fmt.Sprintf("%s depends on %s: %s", p.ImportPath, d, r.Reason))
			}
		}
	}
	sort.Strings(out)
	return out
}

// CheckStdlibOnly reports any import that is neither stdlib nor inside the
// module, including test imports.
func CheckStdlibOnly(module string, pkgs []Package) []string {
	var out []string
	for _, p := range pkgs {
		if p.Standard {
			continue
		}
		all := append(append(append([]string{}, p.Deps...), p.TestImports...), p.XTestImports...)
		for _, d := range all {
			if within(d, module) || isStdlibPath(d) {
				continue
			}
			out = append(out, fmt.Sprintf("%s imports non-stdlib %s", p.ImportPath, d))
		}
	}
	sort.Strings(out)
	return out
}

// isStdlibPath uses the toolchain convention that stdlib paths have no dot
// in their first element. "C" (cgo) is rejected.
func isStdlibPath(p string) bool {
	if p == "C" {
		return false
	}
	first, _, _ := strings.Cut(p, "/")
	return !strings.Contains(first, ".")
}

// CheckGoMod rejects any require directive.
func CheckGoMod(gomod string) []string {
	var out []string
	for i, line := range strings.Split(gomod, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == "require" {
			out = append(out, fmt.Sprintf("go.mod:%d: require is forbidden (stdlib only)", i+1))
		}
	}
	return out
}

// CheckWriterUsage parses non-test files of every module package outside
// WriterAllowed and reports references to entra.Writer, honouring import
// aliases. Dot and blank imports of the entra package are reported too.
func CheckWriterUsage(module string, pkgs []Package, allowed []string) ([]string, error) {
	writerPath := module + "/" + WriterPkg
	var out []string
	for _, p := range pkgs {
		if p.Standard || !within(p.ImportPath, module) || p.ImportPath == writerPath {
			continue
		}
		skip := false
		for _, a := range allowed {
			if within(p.ImportPath, module+"/"+a) {
				skip = true
			}
		}
		if skip {
			continue
		}
		for _, name := range p.GoFiles {
			fset := token.NewFileSet()
			path := p.Dir + "/" + name
			f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return nil, err
			}
			out = append(out, writerRefs(fset, f, writerPath)...)
		}
	}
	sort.Strings(out)
	return out, nil
}

func writerRefs(fset *token.FileSet, f *ast.File, writerPath string) []string {
	local := ""
	var out []string
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != writerPath {
			continue
		}
		local = "entra"
		if imp.Name != nil {
			local = imp.Name.Name
		}
		if local == "." || local == "_" {
			out = append(out, fmt.Sprintf("%s: %q import of %s is forbidden", fset.Position(imp.Pos()), local, writerPath))
			return out
		}
	}
	if local == "" {
		return nil
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == local && sel.Sel.Name == "Writer" {
			out = append(out, fmt.Sprintf("%s: entra.Writer used outside allowed packages", fset.Position(sel.Pos())))
		}
		return true
	})
	return out
}
