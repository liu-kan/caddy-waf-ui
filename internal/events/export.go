package events

import (
	"path/filepath"
	"sort"
)

// ExportRetained migrates pending local history to the separately redacted
// queue. Imported events never become an outbound input. Retrying is safe
// because the export store deduplicates durable node/transaction identities.
func (s *Store) ExportRetained(cloud *Store, policy Redaction) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := map[string]bool{}
	for _, ref := range s.index {
		names[ref.File] = true
	}
	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	for _, name := range sorted {
		var batch []*Event
		if err := walkEventFile(filepath.Join(s.dir, name), func(e *Event, offset int64, _ int) error {
			ref, ok := s.index[e.Key()]
			if !ok || ref.File != name || ref.Offset != offset || e.Source == SourceLoki {
				return nil
			}
			batch = append(batch, policy.Apply(e))
			if len(batch) < maxBatch {
				return nil
			}
			_, err := cloud.AppendBatch(batch, SourceLocal)
			batch = batch[:0]
			return err
		}); err != nil {
			return err
		}
		if len(batch) > 0 {
			if _, err := cloud.AppendBatch(batch, SourceLocal); err != nil {
				return err
			}
		}
	}
	return nil
}
