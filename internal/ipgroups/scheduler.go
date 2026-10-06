package ipgroups

import (
	"context"
	"log/slog"
	"time"
)

// Tick imports every due group once and calls onChange for each group whose
// active list changed.
func (r *Registry) Tick(ctx context.Context, onChange func(name string)) {
	for _, name := range r.Due(r.opts.Now()) {
		if ctx.Err() != nil {
			return
		}
		changed, err := r.Refresh(ctx, name, false)
		if err != nil {
			slog.Warn("IP group refresh failed", "group", name, "error", err)
			continue
		}
		if changed && onChange != nil {
			onChange(name)
		}
	}
}

// Run checks the groups every interval until ctx ends.
func (r *Registry) Run(ctx context.Context, every time.Duration, onChange func(name string)) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		r.Tick(ctx, onChange)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
