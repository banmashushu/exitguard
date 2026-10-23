//go:build windows && amd64

package enforce

import (
	"runtime"
	"testing"
)

func TestNativeWFPReadbackRejectsTamperedOSFilters(t *testing.T) {
	p := Policy{Port: 17890, Programs: []string{`C:\Apps\Claude.exe`}}
	rule := windowsRules(p)[0]
	identity := []byte{1, 2, 3, 4}
	app := blobFor(identity)
	var pinned runtime.Pinner
	pinned.Pin(&app)
	defer pinned.Unpin()
	for _, mutation := range []string{"none", "disabled", "permit", "wrong-port", "other-identity", "missing-condition", "metadata", "weight", "foreign-provider"} {
		filter, conditions, data := makeNativeFilter(rule, &app, Hash(p))
		switch mutation {
		case "disabled":
			filter.Flags |= 0x20
		case "permit":
			filter.Action.Type = 0x1002
		case "wrong-port":
			conditions[1].Value.Value = 0x08080808
		case "other-identity":
			conditions[0].Match = 10
		case "missing-condition":
			filter.Count--
		case "metadata":
			data[0] = 'X'
		case "weight":
			filter.Weight.Value = 0
		case "foreign-provider":
			filter.Provider = &wfpGUID{}
		}
		err := verifyNativeFilter(&filter, rule, &app, Hash(p))
		if (err == nil) != (mutation == "none") {
			t.Errorf("mutation %s accepted=%v: %v", mutation, err == nil, err)
		}
	}
}

func TestNativeWFPReadbackRequiresCompleteExactRuleSet(t *testing.T) {
	rules := windowsRules(Policy{Port: 17890, Programs: []string{`C:\Apps\Claude.exe`}})
	keys := make([]wfpGUID, len(rules))
	for i := range rules {
		keys[i] = guidFromKey(rules[i].Key)
	}
	if !matchingNativeRuleSet(keys, rules) {
		t.Fatal("expected rule set rejected")
	}
	if matchingNativeRuleSet(keys[:len(keys)-1], rules) {
		t.Fatal("missing block accepted")
	}
	keys[0] = wfpGUID{}
	if matchingNativeRuleSet(keys, rules) {
		t.Fatal("unexpected/native permit could be hidden by expected IDs")
	}
}
