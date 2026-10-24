// Package archtest enforces KODIS package boundaries and the stdlib-only
// dependency rule. The checks are pure functions over package metadata so
// that they can be tested against synthetic violations.
package archtest

import (
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
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
		Pkg:       "internal",
		Forbidden: []string{"reflect", "unsafe"},
		Reason:    "reflection and unsafe can reach methods the static boundary checks cannot see",
	},
	{
		Pkg:       "cmd",
		Forbidden: []string{"reflect", "unsafe"},
		Reason:    "reflection and unsafe can reach methods the static boundary checks cannot see",
	},
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
		Pkg:       "internal/audit",
		Forbidden: []string{"internal/execute", "internal/entra", "internal/policy", "internal/plan", "net", "net/http", "os/exec"},
		Reason:    "the audit log records decisions; it must not reach tenant state or make them",
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

// WriterMethods returns the method names of the Writer interface declared
// in dir (the internal/entra source directory). Failing to find the
// interface is an error, so the check cannot silently become a no-op.
func WriterMethods(dir string, goFiles []string) ([]string, error) {
	var out []string
	found := false
	for _, name := range goFiles {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, dir+"/"+name, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok || ts.Name.Name != "Writer" {
				return true
			}
			it, ok := ts.Type.(*ast.InterfaceType)
			if !ok {
				return true
			}
			found = true
			for _, m := range it.Methods.List {
				for _, id := range m.Names {
					out = append(out, id.Name)
				}
			}
			return false
		})
	}
	if !found || len(out) == 0 {
		return nil, fmt.Errorf("no Writer interface with methods found in %s", dir)
	}
	sort.Strings(out)
	return out, nil
}

// CheckWriteCalls reports any selector naming a Writer method in non-test
// files outside the allowed packages. It is name-based and therefore
// conservative: it cannot tell a tenant write from an unrelated method of
// the same name, and it does not need to, because no other code should
// define one. This closes the gap where a Writer is obtained by type
// inference (e.g. tenant.Writer().SetConditionalAccessState(...)) without
// ever naming entra.Writer.
func CheckWriteCalls(module string, pkgs []Package, methods, allowed []string) ([]string, error) {
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
			f, err := parser.ParseFile(fset, p.Dir+"/"+name, nil, parser.SkipObjectResolution)
			if err != nil {
				return nil, err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if ok && slices.Contains(methods, sel.Sel.Name) {
					out = append(out, fmt.Sprintf("%s: %s is a tenant write and may only be called from %v", fset.Position(sel.Pos()), sel.Sel.Name, allowed))
				}
				return true
			})
		}
	}
	sort.Strings(out)
	return out, nil
}

// ConstrainedAllowed lists the only non-test files that may carry a build
// constraint (a //go:build line or a GOOS/GOARCH file name suffix). Files
// excluded from the default build are invisible to `go list`-based checks,
// so every such file is an exception that needs human approval.
var ConstrainedAllowed = []string{
	"internal/approve/owner_other.go",
	"internal/approve/owner_unix.go",
	"internal/audit/lock_other.go",
	"internal/audit/lock_unix.go",
}

// SourcePackages walks root and returns one Package per directory holding
// non-test Go files, with GoFiles listing every such file regardless of
// build constraints, Imports set to the files' direct imports and Deps to
// the direct imports plus every module package reachable through them.
//
// Only directories whose name starts with "." are skipped, because such
// paths cannot be imported. testdata, vendor and "_" directories are
// walked: `./...` ignores them, but they can still be imported explicitly.
//
// Running the existing checks on these packages covers files that
// `go list` leaves out. Deps is computed over all files of every package,
// regardless of whether they would be built together, so it can only
// over-approximate the real dependencies (fail closed).
func SourcePackages(root, module string) ([]Package, error) {
	byDir := map[string]*Package{}
	var order []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != root && strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		dir := filepath.Dir(path)
		p, ok := byDir[dir]
		if !ok {
			rel, err := filepath.Rel(root, dir)
			if err != nil {
				return err
			}
			ip := module
			if rel != "." {
				ip = module + "/" + filepath.ToSlash(rel)
			}
			p = &Package{ImportPath: ip, Dir: dir}
			byDir[dir] = p
			order = append(order, dir)
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			ip, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			if !slices.Contains(p.Imports, ip) {
				p.Imports = append(p.Imports, ip)
			}
		}
		p.GoFiles = append(p.GoFiles, name)
		return nil
	})
	if err != nil {
		return nil, err
	}
	byPath := map[string]*Package{}
	for _, p := range byDir {
		sort.Strings(p.Imports)
		byPath[p.ImportPath] = p
	}
	var out []Package
	for _, dir := range order {
		p := byDir[dir]
		p.Deps = closure(module, p.Imports, byPath)
		out = append(out, *p)
	}
	return out, nil
}

// closure returns imports plus every module package transitively
// imported by the module packages among them.
func closure(module string, imports []string, byPath map[string]*Package) []string {
	seen := map[string]bool{}
	var visit func(ip string)
	visit = func(ip string) {
		if seen[ip] {
			return
		}
		seen[ip] = true
		if q, ok := byPath[ip]; ok && within(ip, module) {
			for _, next := range q.Imports {
				visit(next)
			}
		}
	}
	for _, ip := range imports {
		visit(ip)
	}
	out := make([]string, 0, len(seen))
	for ip := range seen {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

// HasBuildTag reports whether the file has a //go:build or // +build line
// before its package clause.
func HasBuildTag(path string) (bool, error) {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.PackageClauseOnly|parser.ParseComments)
	if err != nil {
		return false, err
	}
	for _, g := range f.Comments {
		if g.Pos() > f.Package {
			break
		}
		for _, c := range g.List {
			if constraint.IsGoBuild(c.Text) || constraint.IsPlusBuild(c.Text) {
				return true, nil
			}
		}
	}
	return false, nil
}

// HasPlatformSuffix reports whether go/build would constrain the file by
// name: after the first "_", a trailing _GOOS, _GOARCH or _GOOS_GOARCH.
// The last element alone decides, since _GOOS_GOARCH also ends in GOARCH.
func HasPlatformSuffix(name string, oses, arches map[string]bool) bool {
	name = strings.TrimSuffix(strings.TrimSuffix(name, ".go"), "_test")
	i := strings.Index(name, "_")
	if i < 0 {
		return false
	}
	l := strings.Split(name[i:], "_")
	last := l[len(l)-1]
	return oses[last] || arches[last]
}

// CheckConstrainedFiles reports constrained non-test files under root that
// are not in allowed (paths relative to root, slash-separated).
func CheckConstrainedFiles(root string, pkgs []Package, allowed []string, oses, arches map[string]bool) ([]string, error) {
	var out []string
	for _, p := range pkgs {
		for _, name := range p.GoFiles {
			path := filepath.Join(p.Dir, name)
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return nil, err
			}
			tagged, err := HasBuildTag(path)
			if err != nil {
				return nil, err
			}
			if (tagged || HasPlatformSuffix(name, oses, arches)) && !slices.Contains(allowed, filepath.ToSlash(rel)) {
				out = append(out, fmt.Sprintf("%s: build-constrained file is not in ConstrainedAllowed; constrained files escape go list-based boundary checks", rel))
			}
		}
	}
	sort.Strings(out)
	return out, nil
}
