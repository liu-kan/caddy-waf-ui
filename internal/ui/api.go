package ui

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
	"github.com/developmi/caddy-waf-ui/internal/iprules"
	"github.com/developmi/caddy-waf-ui/internal/service"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// ModeRequest defines the expected body for changing the mode of the WAF.
// Reason (optional) is recorded in the change journal.
type ModeRequest struct {
	Mode   domain.WAFMode `json:"mode"`
	Reason string         `json:"reason,omitempty"`
}

// ExclusionsRequest defines the expected body for updating exclusions.
type ExclusionsRequest struct {
	Exclusions []waf.Exclusion `json:"exclusions"`
	Reason     string          `json:"reason,omitempty"`
}

// RollbackRequest defines the expected body for restoring a snapshot:
// the full backup name ("{ISO8601}.{type}.conf", contract D2).
type RollbackRequest struct {
	Backup string `json:"backup"`
	Reason string `json:"reason,omitempty"`
}

// reasonOf returns the change reason of an API call: the payload field, or
// the X-Change-Reason header for payloads without one (IP rules).
func reasonOf(r *http.Request, body string) string {
	if body != "" {
		return body
	}
	return r.Header.Get("X-Change-Reason")
}

// maxBodyBytes bounds the size of the JSON API bodies (defense against
// memory DoS, finding J1): 1 MiB is enough for the configuration payloads
// managed by the UI.
const maxBodyBytes = 1 << 20

// decodeJSONBody decodes the JSON body of a request with a size cap. A body
// over the limit responds 413; any other decode error responds 400 (same
// error style as the previous handlers).
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "Payload too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "Invalid payload", http.StatusBadRequest)
		}
		return err
	}
	return nil
}

// clientIP extracts the client IP from r.RemoteAddr (host:port format) so
// the remote_ip field of the audit log does not drag the port along.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// writeJSON responds with a plain JSON confirmation (REST contract).
func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// HandleSetMode changes the WAF engine mode of a domain (RESTful).
// The domain arrives as a path param (Go 1.22+ ServeMux) and the shared
// chain (validate → backup → generate → write → reload → audit) lives in
// service.
func HandleSetMode(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")

	var req ModeRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		return
	}

	if err := service.ApplyMode(actor(r, reasonOf(r, req.Reason)), domainName, req.Mode); err != nil {
		if errors.Is(err, service.ErrInvalidDomain) {
			http.Error(w, "Invalid domain", http.StatusBadRequest)
			return
		}
		if errors.Is(err, service.ErrInvalidMode) {
			http.Error(w, "Invalid WAF mode", http.StatusBadRequest)
			return
		}
		http.Error(w, "Error applying the configuration", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, `{"status":"success"}`)
}

// HandleSetExclusions updates the CRS exclusions of a domain (RESTful).
// The payload validation happens BEFORE the chain (defense in depth: the
// chain re-validates): an invalid payload is 400, not 500.
func HandleSetExclusions(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")

	var req ExclusionsRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		return
	}

	if err := waf.ValidateExclusions(req.Exclusions); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := service.ApplyExclusions(actor(r, reasonOf(r, req.Reason)), domainName, req.Exclusions); err != nil {
		if errors.Is(err, service.ErrInvalidDomain) {
			http.Error(w, "Invalid domain", http.StatusBadRequest)
			return
		}
		http.Error(w, "Error applying the configuration", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, `{"status":"success"}`)
}

// HandleSetIPRules updates the allow/deny lists of a domain (RESTful).
// The payload validation happens BEFORE the chain (defense in depth: the
// chain re-validates): an invalid payload is 400, not 500.
func HandleSetIPRules(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")

	var req iprules.IPRules
	if err := decodeJSONBody(w, r, &req); err != nil {
		return
	}

	if err := iprules.ValidateIPRules(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := service.ApplyIPRules(actor(r, reasonOf(r, "")), domainName, req); err != nil {
		if errors.Is(err, service.ErrInvalidDomain) {
			http.Error(w, "Invalid domain", http.StatusBadRequest)
			return
		}
		http.Error(w, "Error applying the configuration", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, `{"status":"success"}`)
}

// HandleListBackups lists the configuration snapshots of a domain (RESTful,
// backup-recovery spec). Without backups it responds 200 with [].
func HandleListBackups(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")

	snapshots, err := files.ListBackups(domainName)
	if err != nil {
		http.Error(w, "Error listing backups", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snapshots)
}

// HandleRollback restores a configuration snapshot of a domain (RESTful):
// the body carries the full backup name and the shared chain runs validate →
// back up → restore → reload → audit.
func HandleRollback(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")

	var req RollbackRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		return
	}

	if err := service.ApplyRollback(actor(r, reasonOf(r, req.Reason)), domainName, req.Backup); err != nil {
		if errors.Is(err, service.ErrInvalidDomain) {
			http.Error(w, "Invalid domain", http.StatusBadRequest)
			return
		}
		if errors.Is(err, files.ErrInvalidBackup) {
			http.Error(w, "Invalid configuration snapshot", http.StatusBadRequest)
			return
		}
		http.Error(w, "Error restoring the configuration", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, `{"status":"success"}`)
}
