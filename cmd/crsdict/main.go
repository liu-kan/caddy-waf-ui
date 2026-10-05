// Command crsdict generates the embedded rule dictionary.
//
// -rules is the authoritative ruleset: normally the "rules" folder of the
// github.com/corazawaf/coraza-coreruleset/v4 module compiled into the backend
// image (fetched with `go mod download`, see the Makefile target crs-dict).
// Its packaged copies strip comments, so -docs optionally points to the
// upstream coreruleset tree of the same version for descriptions and links.
// Both are only read from disk; neither becomes a dependency of this
// stdlib-only application.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/developmi/caddy-waf-ui/internal/crs"
)

type options struct {
	rules, rulesLabel, rulesURL string
	docs, docsLabel, docsURL    string
	out                         string
}

func main() {
	var o options
	flag.StringVar(&o.rules, "rules", "", "authoritative ruleset directory (coraza-coreruleset rules/)")
	flag.StringVar(&o.rulesLabel, "source", "", "source label, e.g. github.com/corazawaf/coraza-coreruleset/v4@v4.25.0")
	flag.StringVar(&o.rulesURL, "url", "", "link base for -rules files, ending in /")
	flag.StringVar(&o.docs, "docs", "", "optional upstream CRS tree of the same version (comments, links)")
	flag.StringVar(&o.docsLabel, "docs-source", "", "docs label, e.g. github.com/coreruleset/coreruleset@v4.25.0")
	flag.StringVar(&o.docsURL, "docs-url", "", "link base for -docs files, ending in /")
	flag.StringVar(&o.out, "out", "internal/crs/data/crs-dictionary.json.gz", "output file")
	flag.Parse()
	if err := run(o); err != nil {
		slog.Error("crsdict failed", "error", err)
		os.Exit(1)
	}
}

func run(o options) error {
	if o.rules == "" {
		return fmt.Errorf("-rules is required")
	}
	dict, err := crs.Build(os.DirFS(o.rules), o.rulesLabel, o.rulesURL)
	if err != nil {
		return err
	}
	if dict.Len() == 0 {
		return fmt.Errorf("no rules found below %s", o.rules)
	}
	if o.docs != "" {
		// An upstream checkout keeps its rules in rules/ next to tests and
		// tooling with example ids; only the rules folder is documentation.
		docsDir, docsURL := o.docs, o.docsURL
		if info, err := os.Stat(filepath.Join(o.docs, "rules")); err == nil && info.IsDir() {
			docsDir = filepath.Join(o.docs, "rules")
			if docsURL != "" {
				docsURL += "rules/"
			}
		}
		docs, err := crs.Build(os.DirFS(docsDir), o.docsLabel, docsURL)
		if err != nil {
			return fmt.Errorf("docs: %w", err)
		}
		if docs.CRSVersion != dict.CRSVersion {
			return fmt.Errorf("docs CRS %s does not match ruleset CRS %s", docs.CRSVersion, dict.CRSVersion)
		}
		dict.ApplyDocs(docs, o.docsLabel)
	}
	var buf bytes.Buffer
	if err := dict.Encode(&buf); err != nil {
		return err
	}
	// Generated source asset: world-readable like the rest of the tree.
	if err := os.WriteFile(o.out, buf.Bytes(), 0o644); err != nil { //nolint:gosec // G306: repository asset, not a secret.
		return err
	}
	commented := 0
	for _, r := range dict.Rules {
		if r.Comment != "" {
			commented++
		}
	}
	fmt.Printf("wrote %s: %d rules (%d with descriptions), CRS %s\n", o.out, dict.Len(), commented, dict.CRSVersion)
	return nil
}
