// Package model defines the configuration and status shared by the local UI and guard.
package model

type Config struct {
	Mode                  string   `json:"mode"`
	EnforcementMode       string   `json:"enforcementMode"`
	AutoRecover           bool     `json:"autoRecover"`
	ExpectedIPs           []string `json:"expectedIPs"`
	ProxyURL              string   `json:"proxyURL"`
	ManagedSubscriptionID string   `json:"managedSubscriptionID,omitempty"`
	ManagedNodeID         string   `json:"managedNodeID,omitempty"`
	PreProxyURL           string   `json:"preProxyURL,omitempty"`
	RemoteProfileID       string   `json:"remoteProfileID,omitempty"`
	ClashControllerURL    string   `json:"clashControllerURL"`
	ClashSelector         string   `json:"clashSelector"`
	ClashNode             string   `json:"clashNode"`
	TunnelInterface       string   `json:"tunnelInterface"`
	DNSResolverURL        string   `json:"dnsResolverURL"`
	DNSBootstrapIP        string   `json:"dnsBootstrapIP"`
	ProbeURL              string   `json:"probeURL"`
	ProxyPort             uint16   `json:"proxyPort"`
	Programs              []string `json:"programs"`
	BundleIDs             []string `json:"bundleIDs"`
}

// RemoteProfile is a public summary. Account names and passwords remain in the
// private profile library and are never included in UI snapshots.
type RemoteProfile struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	ProxyURL               string   `json:"proxyURL"`
	ExpectedIPs            []string `json:"expectedIPs"`
	HasCredentials         bool     `json:"hasCredentials"`
	PreProxyURL            string   `json:"preProxyURL,omitempty"`
	HasPreProxyCredentials bool     `json:"hasPreProxyCredentials"`
	ManagedSubscriptionID  string   `json:"managedSubscriptionID,omitempty"`
	ManagedNodeID          string   `json:"managedNodeID,omitempty"`
}

// RemoteProfileInput uses keep, replace or clear to make account changes
// explicit. A blank ID creates a new profile; only selection activates one.
type RemoteProfileInput struct {
	ID                       string   `json:"id"`
	Name                     string   `json:"name"`
	ProxyURL                 string   `json:"proxyURL"`
	ExpectedIPs              []string `json:"expectedIPs"`
	CredentialAction         string   `json:"credentialAction"`
	Username                 string   `json:"-"`
	Password                 string   `json:"-"`
	PreProxyURL              string   `json:"preProxyURL,omitempty"`
	PreProxyUsername         string   `json:"-"`
	PreProxyPassword         string   `json:"-"`
	ClearPreProxyCredentials bool     `json:"-"`
	ManagedSubscriptionID    string   `json:"managedSubscriptionID,omitempty"`
	ManagedNodeID            string   `json:"managedNodeID,omitempty"`
}

type Status struct {
	NativeState                    string `json:"nativeState,omitempty"`
	NativeReason                   string `json:"nativeReason,omitempty"`
	EnforcementMode                string `json:"enforcementMode"`
	UpstreamCredentialsSet         bool   `json:"upstreamCredentialsSet"`
	UpstreamCredentialsSaved       bool   `json:"upstreamCredentialsSaved"`
	UpstreamCredentialsRestored    bool   `json:"upstreamCredentialsRestored"`
	CredentialPersistenceSupported bool   `json:"credentialPersistenceSupported"`
	SessionRevision                uint64 `json:"sessionRevision"`
	State                          string `json:"state"`
	Reason                         string `json:"reason"`
	ObservedIP                     string `json:"observedIP"`
	FilterActive                   bool   `json:"filterActive"`
	PolicyHash                     string `json:"policyHash"`
	ProxyAddress                   string `json:"proxyAddress"`
	Platform                       string `json:"platform"`
	CheckedAt                      string `json:"checkedAt"`
	RecoveryAttempt                int    `json:"recoveryAttempt,omitempty"`
	RecoveryMaxAttempts            int    `json:"recoveryMaxAttempts,omitempty"`
	NextRetryAt                    string `json:"nextRetryAt,omitempty"`
}

type Event struct {
	At      string `json:"at"`
	State   string `json:"state"`
	Message string `json:"message"`
}

// Subscription sources contain credentials and never belong to UI snapshots.
type SubscriptionInput struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	URL           string `json:"-"`
	Content       []byte `json:"-"`
	DownloadRoute string `json:"downloadRoute,omitempty"`
}
type SubscriptionSummary struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	SourceKind         string `json:"sourceKind"`
	UpdatedAt          string `json:"updatedAt"`
	NodeCount          int    `json:"nodeCount"`
	SupportedNodeCount int    `json:"supportedNodeCount"`
	DownloadRoute      string `json:"downloadRoute"`
}
type SubscriptionNode struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	Type                 string `json:"type"`
	Supported            bool   `json:"supported"`
	Reason               string `json:"reason,omitempty"`
	SkipsTLSVerification bool   `json:"skipsTLSVerification,omitempty"`
}
