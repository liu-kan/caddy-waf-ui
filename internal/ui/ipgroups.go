package ui

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/config"
	"github.com/developmi/caddy-waf-ui/internal/ipgroups"
	"github.com/developmi/caddy-waf-ui/internal/service"
)

// importTimeout bounds a download started from the UI or the API.
const importTimeout = 90 * time.Second

// ipGroupView is a group with the sites that use it.
type ipGroupView struct {
	ipgroups.Group
	// Sites use the group in their policy; Stale sites still load an older
	// list (publishing the current one failed).
	Sites []string `json:"sites"`
	Stale []string `json:"stale,omitempty"`
}

func groupViews() ([]ipGroupView, error) {
	reg := service.IPGroups()
	if reg == nil {
		return nil, service.ErrIPGroupsUnavailable
	}
	usage, stale, err := service.IPGroupPublication()
	views := []ipGroupView{}
	for _, g := range reg.Groups() {
		views = append(views, ipGroupView{Group: g, Sites: usage[g.Name], Stale: stale[g.Name]})
	}
	return views, err
}

// groupMember reports IP group membership for impact estimates.
func groupMember() func(string, netip.Addr) bool {
	if reg := service.IPGroups(); reg != nil {
		return reg.Contains
	}
	return nil
}

func groupNames() []string {
	reg := service.IPGroups()
	if reg == nil {
		return nil
	}
	var out []string
	for _, g := range reg.Groups() {
		out = append(out, g.Name)
	}
	return out
}

func buildIPGroupsData(q url.Values, d *wafData) {
	d.IPGroupDir = config.IPGroupDir()
	d.IPGroupMax = ipgroups.MaxPrefixes
	views, err := groupViews()
	if errors.Is(err, service.ErrIPGroupsUnavailable) {
		return
	}
	d.IPGroupsReady = true
	d.IPGroupViews = views
	if err != nil {
		d.FormError = "Could not read the site policies: " + err.Error()
	}
	d.IPGroupForm = ipgroups.Definition{Source: ipgroups.SourceURL, Refresh: ipgroups.DefaultRefresh.String()}
	if name := q.Get("edit"); name != "" {
		if g, ok := service.IPGroups().Get(name); ok {
			d.IPGroupForm = g.Definition
		}
	}
	if ip := strings.TrimSpace(q.Get("ip")); ip != "" {
		d.LookupIP = ip
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			d.LookupError = "Not an IP address."
			return
		}
		d.LookupGroups = service.IPGroups().Lookup(addr)
		d.LookupDone = true
	}
}

func definitionFromForm(r *http.Request) ipgroups.Definition {
	return ipgroups.Definition{Name: strings.TrimSpace(r.FormValue("name")), Source: r.FormValue("source"),
		File: r.FormValue("file"), URL: r.FormValue("url"), Refresh: strings.TrimSpace(r.FormValue("refresh")), Note: r.FormValue("note")}
}

// HandleFormIPGroupSave creates or updates a group and imports it.
func HandleFormIPGroupSave(w http.ResponseWriter, r *http.Request) {
	def := definitionFromForm(r)
	ctx, cancel := context.WithTimeout(r.Context(), importTimeout)
	defer cancel()
	if _, err := service.PutIPGroup(ctx, actor(r, r.FormValue("reason")), def); err != nil {
		renderTab(w, r, "ipgroups", "", func(d *pageData) {
			d.FormError, d.IPGroupForm = err.Error(), def
		})
		return
	}
	redirectAfterForm(w, r, "success")
}

// HandleFormIPGroupAction refreshes, approves, discards, republishes or
// deletes a group.
func HandleFormIPGroupAction(w http.ResponseWriter, r *http.Request) {
	name, op := r.PathValue("name"), r.PathValue("op")
	a := actor(r, r.FormValue("reason"))
	ctx, cancel := context.WithTimeout(r.Context(), importTimeout)
	defer cancel()
	var err error
	switch op {
	case "refresh":
		_, err = service.RefreshIPGroup(ctx, a, name, true)
	case "approve":
		err = service.ApproveIPGroup(a, name)
	case "discard":
		err = service.DiscardIPGroup(a, name)
	case "publish":
		err = service.ReapplyIPGroup(a, name)
	case "delete":
		err = service.DeleteIPGroup(a, name)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		renderTab(w, r, "ipgroups", "", func(d *pageData) { d.FormError = err.Error() })
		return
	}
	redirectAfterForm(w, r, "success")
}

// IPGroupRequest is the body of PUT /api/ipgroups/{name}.
type IPGroupRequest struct {
	ipgroups.Definition
	Reason string `json:"reason,omitempty"`
}

// HandleAPIIPGroups lists the groups with the sites that use them.
func HandleAPIIPGroups(w http.ResponseWriter, _ *http.Request) {
	views, err := groupViews()
	if errors.Is(err, service.ErrIPGroupsUnavailable) {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		http.Error(w, "Error reading the site policies", http.StatusInternalServerError)
		return
	}
	writeJSONValue(w, http.StatusOK, map[string]any{"groups": views})
}

// HandleAPIIPGroupPut creates or updates a group and imports it.
func HandleAPIIPGroupPut(w http.ResponseWriter, r *http.Request) {
	var req IPGroupRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		return
	}
	req.Name = r.PathValue("name")
	if _, err := ipgroups.Validate(req.Definition); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), importTimeout)
	defer cancel()
	g, err := service.PutIPGroup(ctx, actor(r, reasonOf(r, req.Reason)), req.Definition)
	if err != nil {
		writeGroupError(w, err)
		return
	}
	writeJSONValue(w, http.StatusOK, g)
}

// HandleAPIIPGroupDelete deletes a group that no policy uses.
func HandleAPIIPGroupDelete(w http.ResponseWriter, r *http.Request) {
	if err := service.DeleteIPGroup(actor(r, reasonOf(r, "")), r.PathValue("name")); err != nil {
		writeGroupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, `{"status":"success"}`)
}

// HandleAPIIPGroupAction refreshes (?force=true ignores the change
// detection), approves or discards a group update.
func HandleAPIIPGroupAction(w http.ResponseWriter, r *http.Request) {
	name, op := r.PathValue("name"), r.PathValue("op")
	a := actor(r, reasonOf(r, ""))
	ctx, cancel := context.WithTimeout(r.Context(), importTimeout)
	defer cancel()
	var (
		changed bool
		err     error
	)
	switch op {
	case "refresh":
		changed, err = service.RefreshIPGroup(ctx, a, name, r.URL.Query().Get("force") == "true")
	case "approve":
		err, changed = service.ApproveIPGroup(a, name), true
	case "discard":
		err = service.DiscardIPGroup(a, name)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		if op == "refresh" && !errors.Is(err, ipgroups.ErrNotFound) && !errors.Is(err, service.ErrIPGroupsUnavailable) {
			// The source could not be read or parsed.
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeGroupError(w, err)
		return
	}
	g, _ := service.IPGroups().Get(name)
	writeJSONValue(w, http.StatusOK, map[string]any{"changed": changed, "group": g})
}

// HandleAPIIPGroupLookup returns the groups that contain an address.
func HandleAPIIPGroupLookup(w http.ResponseWriter, r *http.Request) {
	reg := service.IPGroups()
	if reg == nil {
		http.Error(w, service.ErrIPGroupsUnavailable.Error(), http.StatusServiceUnavailable)
		return
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(r.URL.Query().Get("ip")))
	if err != nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}
	groups := reg.Lookup(addr)
	if groups == nil {
		groups = []string{}
	}
	writeJSONValue(w, http.StatusOK, map[string]any{"ip": addr.String(), "groups": groups})
}

func writeGroupError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ipgroups.ErrNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, service.ErrIPGroupInUse):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, service.ErrIPGroupsUnavailable):
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
