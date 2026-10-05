package crs

import (
	_ "embed"
	"encoding/json"
	"strconv"
	"sync"
)

// notesZH holds curated Chinese explanations: per-rule notes for frequently
// seen rules and per-category notes as a fallback for every other rule.
//
//go:embed data/notes-zh.json
var notesZH []byte

type notesFile struct {
	Version    string            `json:"version"`
	Categories map[string]string `json:"categories"`
	Rules      map[string]string `json:"rules"`
}

var (
	notesOnce sync.Once
	notes     notesFile
	notesErr  error
)

func loadNotes() notesFile {
	notesOnce.Do(func() {
		notesErr = json.Unmarshal(notesZH, &notes)
	})
	if notesErr != nil {
		panic("embedded rule notes: " + notesErr.Error())
	}
	return notes
}

// Note returns the curated Chinese explanation of a rule and of its
// category. Either may be empty.
func Note(r Rule) (rule, category string) {
	n := loadNotes()
	return n.Rules[strconv.Itoa(r.ID)], n.Categories[r.Category]
}
