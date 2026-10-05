package ui

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/analysis"
	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

//go:embed templates
var templateFS embed.FS

// funcMap exposes template helpers: "date" (date with Go layout, replaces
// the |date filter of Jinja) and "slug" (normalization D4, replaces
// DomainClean).
var funcMap = template.FuncMap{
	"date": func(value any, layout string) string {
		switch t := value.(type) {
		case time.Time:
			return t.Format(layout)
		case string:
			if parsed, err := time.Parse(time.RFC3339, t); err == nil {
				return parsed.Format(layout)
			}
			return t
		default:
			return fmt.Sprint(value)
		}
	},
	"slug": domain.DomainSlug,
	"add":  func(a, b int) int { return a + b },
	"sub":  func(a, b int) int { return a - b },
	"mul":  func(a, b int) int { return a * b },
	"list": func(values ...int) []int { return values },
	// fpExclusionURL opens the exclusions form prefilled with the narrowest
	// scope of a false-positive candidate.
	"fpExclusionURL": func(c analysis.FPCandidate) string {
		return exclusionURL(c.Site, c.Rule, c.Path, waf.PathExact, paramFromVar(c.Var))
	},
}

// pageNames are the pages that define the "content" block over "base".
// The file name matches the value of ?tab=.
var pageNames = []string{"overview", "sites", "exclusions", "iprules", "logs", "rollback",
	"events", "event", "rules", "analysis", "policy"}

// templates contains a template set per page (base + content) and a
// standalone template for login. They are parsed once when the package
// starts.
var templates = parseTemplates()

// parseTemplates builds the template map: for each page, base.html +
// {page}.html are parsed in their own set (avoids collisions of the
// "content" block between pages); login.html is a complete document.
func parseTemplates() map[string]*template.Template {
	m := make(map[string]*template.Template, len(pageNames)+1)
	for _, page := range pageNames {
		t := template.New("base").Funcs(funcMap)
		t = template.Must(t.Parse(mustRead("templates/base.html")))
		t = template.Must(t.Parse(mustRead("templates/" + page + ".html")))
		m[page] = t
	}
	m["login"] = template.Must(template.New("login").Funcs(funcMap).Parse(mustRead("templates/login.html")))
	return m
}

// mustRead reads an embedded file; on an error the program cannot work
// (mandatory templates), so it panics at init.
func mustRead(path string) string {
	content, err := fs.ReadFile(templateFS, path)
	if err != nil {
		panic(fmt.Sprintf("embedded template %s: %v", path, err))
	}
	return string(content)
}
