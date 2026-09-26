// Command gen-config-docs generates docs/CONFIGURATION.md from
// internal/config/config.go — the same idea as go-wallet-backend's own
// developer_tools/scripts/gen_config_docs (parse the real config source,
// never hand-maintain a doc that drifts), adapted to this repo's actual
// config style: plain os.Getenv/getXxxEnv(key, default) calls inside each
// Load*() function, not struct tags (yaml/envconfig) on the config
// structs themselves — there's nothing for a tag-based parser to read
// here, so this walks each Load*() function's source text instead to
// find env var name + default + required-ness, keyed back to the struct
// field's doc comment for the description.
//
// Usage:
//
//	go run ./tools/gen-config-docs [-root .] [-out docs/CONFIGURATION.md]
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// field is one documented struct field.
type field struct {
	name string
	doc  string // from the field's Go doc/inline comment
}

// structInfo is one parsed `type XConfig struct{...}` declaration, in
// field-declaration order (matches the order fields are documented in).
type structInfo struct {
	name   string
	fields []field
	order  map[string]int
}

// envBinding is what one field resolves to at runtime, extracted from its
// Load*() function's source text (see bindEnvVars).
type envBinding struct {
	envVar   string
	defValue string // display text; empty if required has no default
	required bool
	note     string // e.g. "JSON object", "comma-separated list"
}

func main() {
	root := flag.String("root", ".", "workspace root")
	out := flag.String("out", "docs/CONFIGURATION.md", "output path relative to root")
	flag.Parse()

	srcPath := filepath.Join(*root, "internal/config/config.go")
	src, err := os.ReadFile(srcPath)
	if err != nil {
		log.Fatalf("reading %s: %v", srcPath, err)
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, srcPath, src, parser.ParseComments)
	if err != nil {
		log.Fatalf("parsing %s: %v", srcPath, err)
	}

	structs := parseStructs(file)
	consts := parseConsts(file)

	type serviceDoc struct {
		binary     string
		structName string
		bindings   map[string]envBinding
	}
	services := []serviceDoc{
		{"cmd/as", "ASConfig", nil},
		{"cmd/ingestion-service", "IngestionConfig", nil},
		{"cmd/verifier-service", "VerifierConfig", nil},
		{"cmd/ingress-router", "IngressConfig", nil},
	}
	loadFuncName := map[string]string{
		"ASConfig":        "LoadAS",
		"IngestionConfig": "LoadIngestion",
		"VerifierConfig":  "LoadVerifier",
		"IngressConfig":   "LoadIngress",
	}

	for i, svc := range services {
		body := funcBodyText(fset, file, src, loadFuncName[svc.structName])
		if body == "" {
			log.Fatalf("could not find function %s in %s", loadFuncName[svc.structName], srcPath)
		}
		services[i].bindings = bindEnvVars(body, consts)
	}

	var b strings.Builder
	b.WriteString("<!-- Regenerate with: go run ./tools/gen-config-docs -->\n\n")
	b.WriteString("# Configuration Reference\n\n")
	b.WriteString("Every field is set purely from environment variables (docs/design.md §12) — ")
	b.WriteString("no YAML/config-file convention at this scale. `Required` fields with no default ")
	b.WriteString("make the binary refuse to start rather than run with a guessed value.\n\n")
	b.WriteString("## Table of Contents\n\n")
	for _, svc := range services {
		anchor := strings.ToLower(strings.ReplaceAll(svc.binary, "/", ""))
		fmt.Fprintf(&b, "- [%s](#%s)\n", svc.binary, anchor)
	}
	b.WriteString("\n---\n\n")

	for _, svc := range services {
		si, ok := structs[svc.structName]
		if !ok {
			log.Fatalf("struct %s not found", svc.structName)
		}
		fmt.Fprintf(&b, "## %s\n\n", svc.binary)
		fmt.Fprintf(&b, "Config struct: `internal/config.%s`\n\n", svc.structName)
		b.WriteString("| Field | Env Variable | Default | Description |\n")
		b.WriteString("|-------|-------------|---------|-------------|\n")
		for _, f := range si.fields {
			eb, hasBinding := svc.bindings[f.name]
			envVar, def := "—", "—"
			if hasBinding {
				envVar = "`" + eb.envVar + "`"
				switch {
				case eb.required:
					def = "*(required)*"
				case eb.defValue != "":
					def = "`" + eb.defValue + "`"
				}
				if eb.note != "" {
					def += " (" + eb.note + ")"
				}
			}
			desc := f.doc
			desc = strings.ReplaceAll(desc, "|", "\\|")
			desc = strings.ReplaceAll(desc, "\n", " ")
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", f.name, envVar, def, desc)
		}
		b.WriteString("\n")
	}

	outPath := filepath.Join(*root, *out)
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		log.Fatalf("creating output dir: %v", err)
	}
	if err := os.WriteFile(outPath, []byte(b.String()), 0o644); err != nil {
		log.Fatalf("writing %s: %v", outPath, err)
	}
	fmt.Printf("Generated %s (%d services)\n", outPath, len(services))
}

// parseStructs extracts every `type XConfig struct{...}` in file, in
// field-declaration order, with each field's doc comment.
func parseStructs(file *ast.File) map[string]*structInfo {
	out := make(map[string]*structInfo)
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				continue
			}
			si := &structInfo{name: ts.Name.Name, order: map[string]int{}}
			for _, f := range st.Fields.List {
				if len(f.Names) == 0 {
					continue
				}
				name := f.Names[0].Name
				if !ast.IsExported(name) {
					continue
				}
				doc := cleanComment(f.Doc)
				if doc == "" {
					doc = cleanComment(f.Comment)
				}
				si.order[name] = len(si.fields)
				si.fields = append(si.fields, field{name: name, doc: doc})
			}
			out[si.name] = si
		}
	}
	return out
}

func cleanComment(cg *ast.CommentGroup) string {
	if cg == nil {
		return ""
	}
	var lines []string
	for _, c := range cg.List {
		text := strings.TrimPrefix(c.Text, "//")
		lines = append(lines, strings.TrimSpace(text))
	}
	return strings.TrimSpace(strings.Join(lines, " "))
}

// funcBodyText returns the raw source text of function fnName's body
// (the part between its braces), by mapping its AST position back
// through fset to a byte range in src.
func funcBodyText(fset *token.FileSet, file *ast.File, src []byte, fnName string) string {
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fnName || fd.Body == nil {
			continue
		}
		start := fset.Position(fd.Body.Pos()).Offset
		end := fset.Position(fd.Body.End()).Offset
		return string(src[start:end])
	}
	return ""
}

var (
	// Field: getEnv("VAR", "default") / getIntEnv("VAR", 4) / etc.,
	// directly inside a composite literal.
	reCompositeGetEnv = regexp.MustCompile(`(\w+):\s*get(?:Env|IntEnv|Int64Env|Uint64Env|Float64Env|DurationEnv)\("([A-Z0-9_]+)",\s*([^)]*)\)`)
	// Field: os.Getenv("VAR"), directly inside a composite literal —
	// optional (empty string is a valid, meaningful zero value) unless a
	// later required-check for the same field says otherwise.
	reCompositeOsGetenv = regexp.MustCompile(`(\w+):\s*os\.Getenv\("([A-Z0-9_]+)"\)`)
	// Any other composite-literal field with a plain Go literal default
	// (no env lookup in the literal itself — may be overridden below by
	// a getXxxEnv(..., c.Field) call in the same function).
	reCompositeLiteral = regexp.MustCompile(`(?m)^\s*(\w+):\s*(.+?),\s*(?://.*)?$`)
	// if c.Field, err = getXxxEnv("VAR", <default>); err != nil — <default>
	// is usually a self-reference (c.Field, already set by the composite
	// literal above), but not always (see LIST_CAPACITY): captured
	// directly rather than assumed, so that exception isn't lost.
	reIfGetEnv = regexp.MustCompile(`if c\.(\w+), err = get(?:IntEnv|Int64Env|Uint64Env|Float64Env|DurationEnv)\("([A-Z0-9_]+)",\s*([^)]*)\);`)
	// if c.Field, err = requireECKeyEnv("VAR"); err != nil
	reIfRequireKey = regexp.MustCompile(`if c\.(\w+), err = requireECKeyEnv\("([A-Z0-9_]+)"\);`)
	// c.Field = os.Getenv("VAR")  (bare statement, not composite literal)
	reBareOsGetenv = regexp.MustCompile(`(?m)^\s*c\.(\w+) = os\.Getenv\("([A-Z0-9_]+)"\)\s*$`)
	// A required-check right after a bare/local assignment:
	// if c.Field == "" { ... }   or   if raw == "" { ...
	reRequiredCheck = regexp.MustCompile(`if (?:c\.(\w+)|(\w+)) == "" \{`)
	// local := getEnv("VAR", "default")   /   local := os.Getenv("VAR")
	reLocalGetEnv   = regexp.MustCompile(`(\w+) := getEnv\("([A-Z0-9_]+)",\s*"([^"]*)"\)`)
	reLocalOsGetenv = regexp.MustCompile(`(\w+) := os\.Getenv\("([A-Z0-9_]+)"\)`)
	// json.Unmarshal([]byte(local), &c.Field)
	reJSONUnmarshal = regexp.MustCompile(`json\.Unmarshal\(\[\]byte\((\w+)\), &c\.(\w+)\)`)
	// c.Field = strings.Split(local, ...)
	reStringsSplit = regexp.MustCompile(`c\.(\w+) = strings\.Split\((\w+),`)
)

var (
	reDurTriple = regexp.MustCompile(`^(\d+)\s*\*\s*(\d+)\s*\*\s*time\.(\w+)$`)
	reDurDouble = regexp.MustCompile(`^(\d+)\s*\*\s*time\.(\w+)$`)
	reDurBare   = regexp.MustCompile(`^time\.(\w+)$`)
	reDigits    = regexp.MustCompile(`^\d[\d_]*$`)

	timeUnits = map[string]time.Duration{
		"Nanosecond": time.Nanosecond, "Microsecond": time.Microsecond,
		"Millisecond": time.Millisecond, "Second": time.Second,
		"Minute": time.Minute, "Hour": time.Hour,
	}
)

// renderDefault turns a Go source expression (as captured verbatim from
// a Load*() function) into the value a reader would actually type into
// that env var — resolving named constants, evaluating the handful of
// `N * time.Unit` shapes this file's durations are always written as
// (via the real time package, not a reimplementation of its formatting),
// and stripping Go's `_` digit-group separator, which the strconv
// parsers these env vars go through do not themselves accept. Anything
// else is returned as-is: better an honest Go-source fragment in the
// docs than a silently wrong guess.
func renderDefault(raw string, consts map[string]string) string {
	raw = strings.TrimSpace(raw)
	if v, ok := consts[raw]; ok {
		return v
	}
	if m := reDurTriple.FindStringSubmatch(raw); m != nil {
		n1, _ := strconv.Atoi(m[1])
		n2, _ := strconv.Atoi(m[2])
		if unit, ok := timeUnits[m[3]]; ok {
			return (time.Duration(n1*n2) * unit).String()
		}
	}
	if m := reDurDouble.FindStringSubmatch(raw); m != nil {
		n, _ := strconv.Atoi(m[1])
		if unit, ok := timeUnits[m[2]]; ok {
			return (time.Duration(n) * unit).String()
		}
	}
	if m := reDurBare.FindStringSubmatch(raw); m != nil {
		if unit, ok := timeUnits[m[1]]; ok {
			return unit.String()
		}
	}
	if reDigits.MatchString(raw) {
		return strings.ReplaceAll(raw, "_", "")
	}
	return strings.Trim(raw, `"`)
}

// parseConsts extracts top-level `const NAME = "value"` string
// declarations (e.g. defaultPostgresDSN), so renderDefault can resolve a
// default expressed as a named constant rather than a literal.
func parseConsts(file *ast.File) map[string]string {
	out := make(map[string]string)
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			unquoted, err := strconv.Unquote(lit.Value)
			if err != nil {
				continue
			}
			out[vs.Names[0].Name] = unquoted
		}
	}
	return out
}

// bindEnvVars extracts every field->envBinding pair from one Load*()
// function's source text. See the package doc for why this walks text
// within an AST-located function rather than the AST tree itself: this
// repo's config has no struct tags to key off of, so the useful
// information (which env var, what default, whether it's required) only
// exists in these functions' call sites.
func bindEnvVars(body string, consts map[string]string) map[string]envBinding {
	bindings := make(map[string]envBinding)
	plainLiteral := make(map[string]string) // field -> its composite-literal RHS text, for pattern 3's default

	for _, m := range reCompositeLiteral.FindAllStringSubmatch(body, -1) {
		plainLiteral[m[1]] = strings.TrimSpace(m[2])
	}
	for _, m := range reCompositeGetEnv.FindAllStringSubmatch(body, -1) {
		bindings[m[1]] = envBinding{envVar: m[2], defValue: renderDefault(m[3], consts)}
	}
	for _, m := range reCompositeOsGetenv.FindAllStringSubmatch(body, -1) {
		bindings[m[1]] = envBinding{envVar: m[2]}
	}
	for _, m := range reIfGetEnv.FindAllStringSubmatch(body, -1) {
		field, envVar, arg3 := m[1], m[2], strings.TrimSpace(m[3])
		def := arg3
		if def == "c."+field { // self-reference to the composite-literal default
			def = plainLiteral[field]
		}
		bindings[field] = envBinding{envVar: envVar, defValue: renderDefault(def, consts)}
	}
	for _, m := range reIfRequireKey.FindAllStringSubmatch(body, -1) {
		bindings[m[1]] = envBinding{envVar: m[2], required: true, note: "PEM-encoded EC private key"}
	}
	for _, m := range reBareOsGetenv.FindAllStringSubmatch(body, -1) {
		bindings[m[1]] = envBinding{envVar: m[2]}
	}

	// Local-var patterns (SHARDS, SHARD_REDIS_URLS, SHARD_BACKENDS): find
	// the local binding, then find where that local var is consumed.
	locals := make(map[string]envBinding) // local var name -> binding
	for _, m := range reLocalGetEnv.FindAllStringSubmatch(body, -1) {
		locals[m[1]] = envBinding{envVar: m[2], defValue: m[3]}
	}
	for _, m := range reLocalOsGetenv.FindAllStringSubmatch(body, -1) {
		locals[m[1]] = envBinding{envVar: m[2]}
	}
	for _, m := range reStringsSplit.FindAllStringSubmatch(body, -1) {
		field, local := m[1], m[2]
		if b, ok := locals[local]; ok {
			b.note = "comma-separated list"
			bindings[field] = b
		}
	}
	for _, m := range reJSONUnmarshal.FindAllStringSubmatch(body, -1) {
		local, field := m[1], m[2]
		if b, ok := locals[local]; ok {
			b.note = "JSON object"
			bindings[field] = b
		}
	}

	// Required-checks flip a field (or, transitively, whatever field a
	// local var later feeds into) from "has an empty-string default" to
	// "required, no default" — covers both `if c.Field == ""` and
	// `if localVar == ""` (which then usually feeds a json.Unmarshal
	// into some other field, already resolved above).
	for _, m := range reRequiredCheck.FindAllStringSubmatch(body, -1) {
		field, local := m[1], m[2]
		if field != "" {
			if b, ok := bindings[field]; ok {
				b.required = true
				b.defValue = ""
				bindings[field] = b
			}
			continue
		}
		if l, ok := locals[local]; ok {
			l.required = true
			l.defValue = ""
			locals[local] = l
			// Propagate to whatever field this local var was already
			// attributed to (a json.Unmarshal target, matched above).
			for f, b := range bindings {
				if b.envVar == l.envVar {
					b.required = true
					b.defValue = ""
					bindings[f] = b
				}
			}
		}
	}

	return bindings
}
