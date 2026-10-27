// Package model defines the configuration and status shared by the local UI and guard.
package model

type Config struct {
	Mode               string   `json:"mode"`
	EnforcementMode    string   `json:"enforcementMode"`
	ExpectedIPs        []string `json:"expectedIPs"`
	ProxyURL           string   `json:"proxyURL"`
	ClashControllerURL string   `json:"clashControllerURL"`
	ClashSelector      string   `json:"clashSelector"`
	ClashNode          string   `json:"clashNode"`
	TunnelInterface    string   `json:"tunnelInterface"`
	DNSResolverURL     string   `json:"dnsResolverURL"`
	DNSBootstrapIP     string   `json:"dnsBootstrapIP"`
	ProbeURL           string   `json:"probeURL"`
	ProxyPort          uint16   `json:"proxyPort"`
	Programs           []string `json:"programs"`
	BundleIDs          []string `json:"bundleIDs"`
}

type Status struct {
	NativeState            string `json:"nativeState,omitempty"`
	NativeReason           string `json:"nativeReason,omitempty"`
	EnforcementMode        string `json:"enforcementMode"`
	UpstreamCredentialsSet bool   `json:"upstreamCredentialsSet"`
	SessionRevision        uint64 `json:"sessionRevision"`
	State                  string `json:"state"`
	Reason                 string `json:"reason"`
	ObservedIP             string `json:"observedIP"`
	FilterActive           bool   `json:"filterActive"`
	PolicyHash             string `json:"policyHash"`
	ProxyAddress           string `json:"proxyAddress"`
	Platform               string `json:"platform"`
	CheckedAt              string `json:"checkedAt"`
}

type Event struct {
	At      string `json:"at"`
	State   string `json:"state"`
	Message string `json:"message"`
}
