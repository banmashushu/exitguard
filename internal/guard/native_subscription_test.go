package guard

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"exitguard/internal/model"
	"exitguard/internal/subscription"
)

func TestServiceNativeURIImportPersistsCoreFieldsWithoutStartingNode(t *testing.T) {
	s := profileService(t)
	controller := &fakeManagedController{lease: newFakeManagedLease()}
	s.managed = controller
	s.convertSubscriptionURI = func(_ context.Context, input []string) ([]subscription.URIConversion, error) {
		if len(input) != 1 || input[0] != "hy2://fictitious-secret@node.example:443#Native" { t.Fatal("service bypassed URI converter") }
		return []subscription.URIConversion{{Config: map[string]any{"name": "Native", "type": "hysteria2", "server": "node.example", "port": 443, "password": "fictitious-secret", "obfs": "salamander", "obfs-password": "fictitious-obfs", "fingerprint": "fictitious-pin"}}}, nil
	}
	summary, err := s.ImportSubscription(context.Background(), model.SubscriptionInput{Name: "Native", Content: []byte("hy2://fictitious-secret@node.example:443#Native")})
	if err != nil || summary.SupportedNodeCount != 1 { t.Fatal("service did not use native conversion", err) }
	lib, err := s.readSubscriptions()
	if err != nil { t.Fatal(err) }
	node := lib.Records[0].Nodes[0]
	if node.Config["fingerprint"] != "fictitious-pin" || node.Config["obfs-password"] != "fictitious-obfs" || controller.ensures.Load() != 0 { t.Fatal("native authentication fields were lost or core activated during import") }
	restored, err := New(s.configPath)
	if err != nil { t.Fatal(err) }
	nodes, err := restored.SubscriptionNodes(summary.ID)
	if err != nil || len(nodes) != 1 || !nodes[0].Supported || nodes[0].ID != node.ID { t.Fatal("native identity did not survive real service restart", err) }
}

func TestServiceNativeHelperFailureRetainsLibraryAndActiveSession(t *testing.T) {
	s := profileService(t)
	summary, _ := importedManagedProfile(t, s)
	before, err := os.ReadFile(s.configPath + ".subscriptions.json")
	if err != nil { t.Fatal(err) }
	s.status.State, s.armedIntent = "proxy_active", true
	revision := s.generation
	lease := newFakeManagedLease()
	s.managedLease = lease
	s.convertSubscriptionURI = func(context.Context, []string) ([]subscription.URIConversion, error) { return nil, errors.New("private-helper-stderr") }
	_, err = s.ImportSubscription(context.Background(), model.SubscriptionInput{ID: summary.ID, Name: "Own", Content: []byte("http://node.example:8080#LegacyWouldAccept")})
	if !errors.Is(err, subscription.ErrNativeConversion) || strings.Contains(err.Error(), "private-helper-stderr") { t.Fatal("helper failure fell back or leaked private error") }
	after, readErr := os.ReadFile(s.configPath + ".subscriptions.json")
	if readErr != nil || string(after) != string(before) || s.generation != revision || !lease.Valid() || s.Status().State != "proxy_active" { t.Fatal("failed native conversion changed old snapshot or session") }
}

func TestDefaultServiceURIImportRequiresPackagedHelper(t *testing.T) {
	s := profileService(t)
	_, err := s.ImportSubscription(context.Background(), model.SubscriptionInput{Name: "Fictitious", Content: []byte("http://node.example:8080#LegacyWouldAccept")})
	if !errors.Is(err, subscription.ErrNativeConversion) { t.Fatal("unpackaged service silently used legacy URI parser") }
	if _, err = os.Stat(s.configPath + ".subscriptions.json"); !os.IsNotExist(err) { t.Fatal("failed default conversion wrote library") }
}
