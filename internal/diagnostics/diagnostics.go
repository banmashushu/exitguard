// Package diagnostics collects a small, read-only environment report. It does
// not import guard/enforce or read their configuration, and never assesses protection.
package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Report struct {
	SchemaVersion        int           `json:"schema_version"`
	GeneratedAt          time.Time     `json:"generated_at"`
	Platform             string        `json:"platform"`
	Architecture         string        `json:"architecture"`
	ProtectionAssessed   bool          `json:"protection_assessed"`
	Windows              WindowsInfo   `json:"windows"`
	ApplicationDiscovery string        `json:"application_discovery"`
	Applications         []Application `json:"applications"`
	Loopback             []PortProbe   `json:"loopback"`
}

type WindowsInfo struct {
	Status   string `json:"status"`
	Version  string `json:"version,omitempty"`
	Build    string `json:"build,omitempty"`
	BFE      string `json:"bfe"`
	Elevated string `json:"elevated"`
}

type Application struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Detected string   `json:"detected"`
	Running  string   `json:"running"`
	Paths    []string `json:"paths"`
}

type PortProbe struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
	// nil means unknown (including canceled, timed out or denied). A successful
	// handshake does not identify the service or assess its configuration.
	TCPReachable *bool `json:"tcp_reachable"`
}

type rawApp struct {
	Name, Path string
	Running    bool
}
type platformData struct {
	Windows           WindowsInfo
	Apps              []rawApp
	Homes             []string
	DiscoveryComplete bool
}
type dialFunc func(context.Context, string, string) (net.Conn, error)

func Collect(ctx context.Context) Report {
	return collect(ctx, collectPlatform, (&net.Dialer{}).DialContext)
}

func collect(ctx context.Context, platform func(context.Context) platformData, dial dialFunc) Report {
	data := platform(ctx)
	discovery := "unknown"
	if data.DiscoveryComplete {
		discovery = "limited_running_processes"
	}
	if data.Windows.Status == "unsupported" {
		discovery = "unsupported"
	}
	return Report{
		SchemaVersion: 1, GeneratedAt: time.Now().UTC(), Platform: runtime.GOOS,
		Architecture: runtime.GOARCH, ProtectionAssessed: false, Windows: data.Windows,
		ApplicationDiscovery: discovery,
		Applications:         applicationFacts(data.Apps, data.Homes, data.DiscoveryComplete),
		Loopback:             probePorts(ctx, dial),
	}
}

func unknownWindows(status string) WindowsInfo {
	return WindowsInfo{Status: status, BFE: status, Elevated: status}
}

func probePorts(ctx context.Context, dial dialFunc) []PortProbe {
	results := make([]PortProbe, 0, 7)
	for _, port := range []uint16{7890, 7891, 7892, 7897, 9090, 17890, 17891} {
		result := PortProbe{Host: "127.0.0.1", Port: port}
		probeCtx, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
		conn, err := dial(probeCtx, "tcp4", "127.0.0.1:"+strconv.Itoa(int(port)))
		if err == nil {
			_ = conn.Close() // No read, write, HTTP, DNS or credentials.
			reachable := true
			result.TCPReachable = &reachable
		} else if errors.Is(err, syscall.ECONNREFUSED) || (runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(10061))) {
			// Only a definite connection refusal means false. Access denied, timeout,
			// cancellation and every unrecognized error remain unknown (null).
			reachable := false
			result.TCPReachable = &reachable
		}
		cancel()
		results = append(results, result)
	}
	return results
}

var appDefinitions = []struct {
	id, label   string
	executables []string
}{
	{"clash_party", "Mihomo Party / Clash Party", []string{"mihomo-party.exe", "mihomo party.exe", "clash-party.exe", "clash party.exe"}},
	{"claude", "Claude", []string{"claude.exe"}},
	{"chrome", "Chrome", []string{"chrome.exe"}},
	{"edge", "Edge", []string{"msedge.exe"}},
}

func appID(name string) int {
	for i, app := range appDefinitions {
		for _, executable := range app.executables {
			if strings.EqualFold(name, executable) {
				return i
			}
		}
	}
	return -1
}

func applicationFacts(raw []rawApp, homes []string, complete bool) []Application {
	apps := make([]Application, len(appDefinitions))
	for i, definition := range appDefinitions {
		apps[i] = Application{ID: definition.id, Name: definition.label, Detected: "unknown", Running: "unknown", Paths: []string{}}
		if complete {
			apps[i].Detected, apps[i].Running = "not_detected", "not_detected"
		}
	}
	for _, item := range raw {
		i := appID(item.Name)
		if i < 0 || !item.Running {
			continue
		}
		app := &apps[i]
		app.Detected = "detected"
		if item.Running {
			app.Running = "running"
		}
		// Only drive-rooted paths with the same allowlisted executable basename.
		// UNC/device paths can expose machine names and are deliberately omitted.
		path := strings.ReplaceAll(item.Path, "/", `\`)
		basename := path[strings.LastIndex(path, `\`)+1:]
		if len(path) < 4 || len(path) > 512 || path[1:3] != `:\` || appID(basename) != i || strings.ContainsAny(path, "\r\n\x00") {
			continue
		}
		redacted := redactPath(item.Path, homes)
		duplicate := false
		for _, previous := range app.Paths {
			if strings.EqualFold(previous, redacted) {
				duplicate = true
			}
		}
		if !duplicate && len(app.Paths) < 8 {
			app.Paths = append(app.Paths, redacted)
		}
	}
	return apps
}

var userPrefix = regexp.MustCompile(`(?i)^[a-z]:[\\/]Users[\\/][^\\/]+`)

func redactPath(path string, homes []string) string {
	for _, home := range homes {
		home = strings.TrimRight(home, `/\`)
		if home != "" && len(path) >= len(home) && strings.EqualFold(path[:len(home)], home) && (len(path) == len(home) || path[len(home)] == '\\' || path[len(home)] == '/') {
			return "%USERPROFILE%" + path[len(home):]
		}
	}
	return userPrefix.ReplaceAllString(path, "%USERPROFILE%")
}

// Decode only explicitly allowed fields. Raw PowerShell output and errors never
// become report text. Reject free-form strings even in the allowed OS fields.
func parseWindowsMetadata(output []byte) (platformData, error) {
	var wire struct {
		Version  string `json:"version"`
		Build    string `json:"build"`
		BFE      string `json:"bfe"`
		Elevated string `json:"elevated"`
		Apps     []struct {
			Name string `json:"name"`
			Path string `json:"path"`
		} `json:"apps"`
		AppsKnown bool `json:"apps_known"`
	}
	if err := json.Unmarshal(output, &wire); err != nil {
		return platformData{}, errors.New("Windows metadata unavailable")
	}
	data := platformData{Windows: unknownWindows("unknown"), DiscoveryComplete: wire.AppsKnown}
	if regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,6}){1,3}$`).MatchString(wire.Version) {
		data.Windows.Version = wire.Version
		data.Windows.Status = "available"
	}
	if regexp.MustCompile(`^[0-9]{1,10}$`).MatchString(wire.Build) {
		data.Windows.Build = wire.Build
	}
	switch strings.ToLower(wire.BFE) {
	case "running", "stopped", "paused", "start pending", "stop pending", "continue pending", "pause pending":
		data.Windows.BFE = strings.ToLower(wire.BFE)
	}
	switch wire.Elevated {
	case "yes", "no":
		data.Windows.Elevated = wire.Elevated
	}
	for i, item := range wire.Apps {
		if i >= 32 {
			break
		}
		if appID(item.Name) >= 0 {
			data.Apps = append(data.Apps, rawApp{Name: item.Name, Path: item.Path, Running: true})
		}
	}
	return data, nil
}
