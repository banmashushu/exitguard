package subscription

import (
	"context"
	"errors"
	"exitguard/internal/model"
	"fmt"
	"strings"
	"testing"
)

func TestPrivateLibraryCandidateUpdateAndStrictDecode(t *testing.T) {
	lib := Empty()
	input := model.SubscriptionInput{Name: "Airport", Content: []byte("proxies: [{name: Safe, type: ss, server: node.example, port: 443, cipher: aes-128-gcm, password: node-private-password}]")}
	record, err := lib.Prepare(context.Background(), input, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = lib.Put(record); err != nil {
		t.Fatal(err)
	}
	data, err := Encode(lib)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.Summaries()) != 1 || restored.Summaries()[0].SourceKind != "file" {
		t.Fatal("private library lost summary")
	}
	input.ID = record.ID
	input.Content = []byte("malformed private-source")
	if _, err = lib.Prepare(context.Background(), input, nil); err == nil {
		t.Fatal("bad update candidate accepted")
	}
	if _, err = restored.Node(record.ID, record.Nodes[0].ID); err != nil {
		t.Fatal("failed update lost original")
	}
	if _, err = Decode([]byte(strings.Replace(string(data), `"version":2`, `"version":2,"version":2`, 1))); err == nil {
		t.Fatal("ambiguous store accepted")
	}
}

func TestPreparePreservesOnlySafeSourceFailureCategories(t *testing.T) {
	for _, known := range []error{ErrEmptyResponse, ErrClientDenied} {
		_, e := Empty().Prepare(context.Background(), model.SubscriptionInput{Name: "Fictitious", URL: "https://example.com/private-source"}, func(context.Context, string) ([]byte, error) {
			return nil, fmt.Errorf("private-source-marker: %w", known)
		})
		if !errors.Is(e, known) || strings.Contains(e.Error(), "private-source-marker") {
			t.Fatal("Prepare erased safe category or exposed wrapped response")
		}
	}
}

func TestUnsupportedURIReasonsRemainStrictAndStoreCompatible(t *testing.T) {
	lib := Empty()
	candidate, e := lib.Prepare(context.Background(), model.SubscriptionInput{Name: "Fictitious", Content: []byte("vless://12345678-1234-1234-1234-123456789abc@node.example:443?unsupported=fictitious-secret\nhy2://fictitious-password@node.example:443")}, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = lib.Put(candidate); e != nil {
		t.Fatal(e)
	}
	data, e := Encode(lib)
	if e != nil {
		t.Fatal(e)
	}
	restored, e := Decode(data)
	if e != nil || restored.Records[0].Nodes[0].Type != "vless" || restored.Records[0].Nodes[1].Type != "hysteria2" {
		t.Fatal("safe URI metadata did not survive private storage")
	}
	candidate.Nodes[0].Reason = "private-response-marker"
	lib.Records[0] = candidate
	if _, e = Encode(lib); e == nil {
		t.Fatal("arbitrary response text accepted as persisted reason")
	}
}

func TestDownloadRouteUsesStrictV2AndReadsV1AsDirect(t *testing.T) {
	lib := Empty()
	record, e := lib.Prepare(context.Background(), model.SubscriptionInput{Name: "Fictitious", URL: "https://example.com/private-source", DownloadRoute: "active_exitguard"}, func(context.Context, string) ([]byte, error) {
		return []byte("proxies: [{name: Safe, type: http, server: node.example, port: 443}]"), nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if record.DownloadRoute != "active_exitguard" || record.Summary().DownloadRoute != "active_exitguard" {
		t.Fatal("explicit download route not retained")
	}
	if e = lib.Put(record); e != nil {
		t.Fatal(e)
	}
	wire, e := Encode(lib)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(wire), `"version":2`) {
		t.Fatal("active route stored in a version old readers may accept")
	}
	legacy := strings.Replace(string(wire), `"version":2`, `"version":1`, 1)
	legacy = strings.Replace(legacy, `,"downloadRoute":"active_exitguard"`, "", 1)
	old, e := Decode([]byte(legacy))
	if e != nil || old.Records[0].DownloadRoute != "direct" || old.Summaries()[0].DownloadRoute != "direct" {
		t.Fatal("v1 did not default to direct", e)
	}
	for _, bad := range []string{strings.Replace(string(wire), `"version":2`, `"version":1`, 1), strings.Replace(string(wire), `,"downloadRoute":"active_exitguard"`, "", 1), strings.Replace(string(wire), `"active_exitguard"`, `"unknown"`, 1)} {
		if _, e = Decode([]byte(bad)); e == nil {
			t.Fatal("ambiguous download route accepted")
		}
	}
	file, e := lib.Prepare(context.Background(), model.SubscriptionInput{Name: "File", Content: []byte("proxies: [{name: Safe, type: http, server: node.example, port: 443}]"), DownloadRoute: "active_exitguard"}, nil)
	if e != nil || file.DownloadRoute != "direct" {
		t.Fatal("file import retained an unused network route")
	}
}
