package logs

import "testing"

func TestActualInterruptionOverridesRuleActions(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"{\"transaction\":{\"id\":\"detect\",\"is_interrupted\":false,\"producer\":{\"rule_engine\":\"DetectionOnly\"}},\"messages\":[{\"actionset\":\"deny,log\"}]}", "DETECTED"},
		{"{\"transaction\":{\"id\":\"block\",\"is_interrupted\":true},\"messages\":[{\"actionset\":\"pass,log\"},{\"actionset\":\"deny,log\"}]}", "BLOCKED"},
		{"{\"transaction\":{\"id\":\"allow\",\"is_interrupted\":true},\"messages\":[{\"actionset\":\"allow,log\"}]}", "DETECTED"},
		{"{\"transaction\":{\"id\":\"legacy\",\"action\":\"deny\"}}", "BLOCKED"},
	}
	for _, tc := range cases {
		entry, err := parseLine([]byte(tc.raw))
		if err != nil {
			t.Fatal(err)
		}
		if entry.Action != tc.want {
			t.Errorf("got %s, want %s for %s", entry.Action, tc.want, tc.raw)
		}
	}
}
