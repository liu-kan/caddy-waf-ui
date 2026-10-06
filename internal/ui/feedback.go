package ui

import (
	"log/slog"
	"net/http"

	"github.com/developmi/caddy-waf-ui/internal/feedback"
	"github.com/developmi/caddy-waf-ui/internal/journal"
)

// HandleFormFeedback records the operator's decision on an event (false
// positive, attack or unreviewed). It never changes the WAF configuration.
func HandleFormFeedback(w http.ResponseWriter, r *http.Request) {
	e, err := findRequestEvent(r, r.PathValue("tx"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	a := actor(r, r.FormValue("reason"))
	decision := r.FormValue("decision")
	if err := feedback.Save(feedback.Record{Tx: e.TxID, Node: e.Node, Site: e.Site, Decision: decision, Reason: a.Reason, Actor: a.User}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := journal.Append(journal.Entry{Site: e.Site, Action: "feedback", Summary: decision, Reason: a.Reason, Actor: a.User, RemoteIP: a.RemoteIP, Result: journal.ResultSuccess}); err != nil {
		slog.Warn("could not append to the change journal", "error", err)
	}
	redirectAfterForm(w, r, "success")
}
