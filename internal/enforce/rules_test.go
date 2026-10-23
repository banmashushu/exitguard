package enforce

import "testing"

// These tests catch a missing complement rule or an accidentally broad block:
// exactly the target's TCP connection to 127.0.0.1:17890 must remain possible.
func TestWindowsRulesDenyEveryRouteExceptGuard(t *testing.T) {
	rules := windowsRules(Policy{Port: 17890, Programs: []string{`C:\Apps\Claude.exe`}})
	tests := []struct {
		app              string
		family, protocol int
		address          uint32
		port             uint16
		inbound, blocked bool
	}{
		{`C:\Apps\Claude.exe`, 4, 6, 0x7f000001, 17890, false, false},
		{`C:\Apps\Claude.exe`, 4, 6, 0x7f000001, 7890, false, true},
		{`C:\Apps\Claude.exe`, 4, 6, 0x7f000002, 17890, false, true},
		{`C:\Apps\Claude.exe`, 4, 6, 0x08080808, 17890, false, true},
		{`C:\Apps\Claude.exe`, 4, 17, 0x7f000001, 17890, false, true},
		{`C:\Apps\Claude.exe`, 4, 1, 0x7f000001, 17890, false, true},
		{`C:\Apps\Claude.exe`, 6, 6, 0, 17890, false, true},
		{`C:\Apps\Claude.exe`, 6, 17, 0, 53, false, true},
		{`C:\Apps\Claude.exe`, 4, 6, 0x7f000001, 17890, true, true},
		{`C:\Apps\Unrelated.exe`, 4, 17, 0x08080808, 53, false, false},
	}
	for _, tt := range tests {
		blocked := false
		for _, rule := range rules {
			if rule.Program != tt.app || rule.Family != tt.family || rule.Inbound != tt.inbound {
				continue
			}
			matches := true
			for _, c := range rule.Conditions {
				var actual uint32
				switch c.Field {
				case "address":
					actual = tt.address
				case "port":
					actual = uint32(tt.port)
				case "protocol":
					actual = uint32(tt.protocol)
				default:
					t.Fatal("unknown condition")
				}
				if c.NotEqual {
					matches = matches && actual != c.Value
				} else {
					matches = matches && actual == c.Value
				}
			}
			blocked = blocked || matches
		}
		if blocked != tt.blocked {
			t.Errorf("flow %+v blocked=%v", tt, blocked)
		}
	}
}

func TestWindowsRuleIDsChangeWithPolicy(t *testing.T) {
	p := Policy{Port: 17890, Programs: []string{`C:\A.exe`}}
	a := windowsRules(p)
	p.Port++
	b := windowsRules(p)
	if len(a) != 6 {
		t.Fatalf("missing outbound/inbound/family restrictions: %d", len(a))
	}
	for i := range a {
		if a[i].Key == b[i].Key {
			t.Fatal("stale rule key survives policy change")
		}
	}
}

func TestRuleOwnershipRejectsDifferentStableKeyAndMalformedMetadata(t *testing.T) {
	p := Policy{Port: 17890, Programs: []string{`C:\Apps\Claude.exe`}}
	rule := windowsRules(p)[0]
	data := encodeRuleMetadata(rule, Hash(p))
	if !metadataOwnsRule(data, rule.Key) {
		t.Fatal("valid OS metadata rejected")
	}
	wrongKey := rule.Key
	wrongKey[0] ^= 1
	if metadataOwnsRule(data, wrongKey) {
		t.Fatal("metadata accepted for an unrelated filter GUID")
	}
	if metadataOwnsRule([]byte(`{"owner":"ExitGuard.WFP.v1"}`), rule.Key) {
		t.Fatal("incomplete metadata could authorize deletion")
	}
	if metadataOwnsRule(append(data, []byte(` {}`)...), rule.Key) {
		t.Fatal("trailing metadata accepted")
	}
}
