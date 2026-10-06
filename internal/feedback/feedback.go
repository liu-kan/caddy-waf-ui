// Package feedback keeps operator decisions locally. Heuristic attack and
// false-positive suggestions never automatically become authorization rules.
package feedback

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/config"
	"github.com/developmi/caddy-waf-ui/internal/files"
)

type Record struct {
	Tx       string    `json:"tx"`
	Node     string    `json:"node"`
	Site     string    `json:"site"`
	Decision string    `json:"decision"`
	Reason   string    `json:"reason"`
	Actor    string    `json:"actor,omitempty"`
	Updated  time.Time `json:"updated"`
}

func path(node, tx string) string {
	h := sha256.Sum256([]byte(node + "\x00" + tx))
	return filepath.Join(config.DataDir(), "feedback", hex.EncodeToString(h[:])+".json")
}
func Save(r Record) error {
	if r.Decision != "false_positive" && r.Decision != "attack" && r.Decision != "unreviewed" {
		return errors.New("invalid event decision")
	}
	r.Reason = strings.TrimSpace(r.Reason)
	if r.Tx == "" || len(r.Tx) > 256 || len(r.Node) > 128 || len(r.Reason) > 500 || r.Reason == "" {
		return errors.New("transaction and a reason of 1-500 characters are required")
	}
	r.Updated = time.Now().UTC()
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	p := path(r.Node, r.Tx)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	return files.AtomicWrite(p, b)
}
func Get(node, tx string) (*Record, error) {
	b, err := os.ReadFile(path(node, tx))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
