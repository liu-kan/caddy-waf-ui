package ui

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/events"
)

func findRequestEvent(r *http.Request, tx string) (*events.Event, error) {
	rt := currentRuntime()
	if rt == nil || rt.Store == nil {
		return nil, errors.New("event store unavailable")
	}
	node := r.FormValue("node")
	if e, ok := rt.Store.GetFor(tx, node); ok {
		return e, nil
	}
	if !rt.Loki.Configured() {
		return nil, errors.New("event not found")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	ts, _ := time.Parse(time.RFC3339Nano, r.FormValue("ts"))
	return rt.Loki.Find(ctx, tx, node, ts)
}
