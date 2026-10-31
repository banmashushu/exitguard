package guard

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"exitguard/internal/enforce"
	"exitguard/internal/model"
)

func withEnforcement(t *testing.T, c model.Config, mode string) model.Config {
	t.Helper()
	b, _ := json.Marshal(c)
	var fields map[string]any
	_ = json.Unmarshal(b, &fields)
	fields["enforcementMode"] = mode
	b, _ = json.Marshal(fields)
	if e := json.Unmarshal(b, &c); e != nil {
		t.Fatal(e)
	}
	return c
}

func statusFields(t *testing.T, v any) map[string]any {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	var fields map[string]any
	if e = json.Unmarshal(b, &fields); e != nil {
		t.Fatal(e)
	}
	return fields
}

func TestFreshConfigProxyOnlyAndLegacyStaysRequired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, e := New(path)
	if e != nil {
		t.Fatal(e)
	}
	if c := statusFields(t, s.Config()); c["mode"] != "remote" || c["enforcementMode"] != "proxy-only" {
		t.Fatalf("fresh configuration does not enable ordinary remote proxy setup: %v", c)
	}
	c := validConfig(t)
	b, _ := json.Marshal(c)
	var fields map[string]any
	_ = json.Unmarshal(b, &fields)
	delete(fields, "enforcementMode")
	b, _ = json.Marshal(fields)
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	s, e = New(path)
	if e != nil {
		t.Fatal(e)
	}
	if got := statusFields(t, s.Config())["enforcementMode"]; got != "required" {
		t.Fatalf("legacy config weakened: %v", got)
	}
}

func TestProxyOnlyNeedsNoOSProofOrInstalledTargets(t *testing.T) {
	s := configured(t)
	c := withEnforcement(t, s.Config(), "proxy-only")
	c.Programs, c.BundleIDs = nil, nil
	if e := s.SaveConfig(c); e != nil {
		t.Fatal(e)
	}
	s.inspect = func(context.Context, enforce.Policy) (enforce.Proof, error) {
		t.Error("proxy-only inspected OS enforcement")
		return enforce.Proof{}, errors.New("OS proof unavailable")
	}
	if e := s.Check(context.Background()); e != nil {
		t.Fatal(e)
	}
	ready := s.Status()
	if ready.State != "proxy_ready" || ready.FilterActive {
		t.Fatalf("invalid proxy readiness: %+v", ready)
	}
	if e := s.Arm(context.Background()); e != nil {
		t.Fatal(e)
	}
	active := s.Status()
	if active.State != "proxy_active" || active.FilterActive || active.PolicyHash != "" {
		t.Fatalf("proxy-only claimed enforcement: %+v", active)
	}
	before := statusFields(t, active)["sessionRevision"]
	s.Disarm()
	after := statusFields(t, s.Status())["sessionRevision"]
	if before == nil || before == after {
		t.Fatal("pause did not revoke session revision")
	}
}

func TestProxyCredentialsStayInMemoryAndClearWhenEndpointChanges(t *testing.T) {
	s := configured(t)
	setter, ok := any(s).(interface{ SetProxyCredentials(string, string) error })
	if !ok {
		t.Fatal("service lacks memory-only remote credentials")
	}
	c := withEnforcement(t, s.Config(), "proxy-only")
	c.Mode, c.ProxyURL = "remote", "http://proxy.example:8080"
	if e := s.SaveConfig(c); e != nil {
		t.Fatal(e)
	}
	if e := setter.SetProxyCredentials("fixture-user", "fixture-password"); e != nil {
		t.Fatal(e)
	}
	if statusFields(t, s.Status())["upstreamCredentialsSet"] != true {
		t.Fatal("missing credential-present status")
	}
	b, _ := os.ReadFile(s.configPath)
	snapshot, _ := json.Marshal([]any{s.Config(), s.Status(), s.Events()})
	for _, raw := range []string{string(b), string(snapshot)} {
		if strings.Contains(raw, "fixture-user") || strings.Contains(raw, "fixture-password") {
			t.Fatal("proxy credentials leaked")
		}
	}
	c.ProxyURL = "https://different.example:8443"
	if e := s.SaveConfig(c); e != nil {
		t.Fatal(e)
	}
	if statusFields(t, s.Status())["upstreamCredentialsSet"] != false {
		t.Fatal("credentials retained for another endpoint")
	}
	for _, pair := range [][2]string{{"only-user", ""}, {"", "only-password"}, {"bad:name", "password"}, {"user", "bad\r\npassword"}} {
		if e := setter.SetProxyCredentials(pair[0], pair[1]); e == nil {
			t.Fatal("malformed credentials accepted")
		}
	}
}

func TestInvalidCredentialOrConfigMutationRevokesActiveProxy(t *testing.T) {
	for _, action := range []string{"credentials", "config"} {
		t.Run(action, func(t *testing.T) {
			s := configured(t)
			c := withEnforcement(t, s.Config(), "proxy-only")
			c.Mode, c.ProxyURL = "remote", "http://proxy.example:8080"
			if e := s.SaveConfig(c); e != nil {
				t.Fatal(e)
			}
			s.makeRemoteRoute = func(context.Context, model.Config, string, string) (route, error) {
				return &testRoute{ip: "203.0.113.7"}, nil
			}
			if e := s.SetProxyCredentials("user", "password"); e != nil {
				t.Fatal(e)
			}
			if e := s.Arm(context.Background()); e != nil {
				t.Fatal(e)
			}
			before := s.Status().SessionRevision
			var e error
			if action == "credentials" {
				e = s.SetProxyCredentials("user", "bad\npassword")
			} else {
				c.ProxyURL = "http://user:secret@proxy.example:8080"
				e = s.SaveConfig(c)
			}
			if e == nil {
				t.Fatal("invalid mutation accepted")
			}
			if st := s.Status(); st.State == "proxy_active" || st.SessionRevision == before {
				t.Fatalf("failed mutation retained active session: %+v", st)
			}
		})
	}
}

func TestProxyOnlyHealthSkipsOSAndStrictRemoteRequiresProof(t *testing.T) {
	s := configured(t)
	c := withEnforcement(t, s.Config(), "proxy-only")
	c.Mode, c.ProxyURL = "remote", "http://proxy.example:8080"
	if e := s.SaveConfig(c); e != nil {
		t.Fatal(e)
	}
	s.makeRemoteRoute = func(context.Context, model.Config, string, string) (route, error) {
		return &testRoute{ip: "203.0.113.7"}, nil
	}
	s.inspect = func(context.Context, enforce.Policy) (enforce.Proof, error) {
		return enforce.Proof{}, errors.New("no proof")
	}
	if e := s.Arm(context.Background()); e != nil {
		t.Fatal(e)
	}
	s.health(context.Background())
	if s.Status().State != "proxy_active" {
		t.Fatal("OS proof blocked ordinary proxy health")
	}
	c.EnforcementMode = "required"
	if e := s.SaveConfig(c); e != nil {
		t.Fatal(e)
	}
	if e := s.Arm(context.Background()); e == nil {
		t.Fatal("strict remote mode silently downgraded")
	}
}
