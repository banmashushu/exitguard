package ui

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"strings"
)

const (
	maxWindowsDiscoveryOutput = 32 << 10
	maxWindowsManifest        = 128 << 10
	maxClaudePackages         = 4
)

// These small metadata parsers are platform independent so their containment
// and output-boundary behavior is exercised by tests on the development host.
func claudePackageLocations(data []byte) []string {
	if len(data) > maxWindowsDiscoveryOutput {
		return nil
	}
	var packages []struct{ Name, InstallLocation string }
	if json.Unmarshal(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}), &packages) != nil || len(packages) > maxClaudePackages {
		return nil
	}
	var paths []string
	for _, p := range packages {
		if p.Name == "Claude" && windowsInventoryLocalPath(p.InstallLocation) {
			paths = append(paths, p.InstallLocation)
		}
	}
	return paths
}

func claudeManifestExecutables(data []byte) []string {
	if len(data) > maxWindowsManifest {
		return nil
	}
	var manifest struct {
		XMLName  xml.Name `xml:"Package"`
		Identity struct {
			Name string `xml:"Name,attr"`
		} `xml:"Identity"`
		Applications []struct {
			Executable string `xml:"Executable,attr"`
		} `xml:"Applications>Application"`
	}
	if xml.Unmarshal(data, &manifest) != nil || manifest.Identity.Name != "Claude" {
		return nil
	}
	var paths []string
	seen := make(map[string]bool)
	for _, app := range manifest.Applications {
		path := strings.ReplaceAll(app.Executable, "/", `\`)
		parts := strings.Split(path, `\`)
		if path == "" || len(paths) == maxClaudePackages || !strings.EqualFold(parts[len(parts)-1], "Claude.exe") || !windowsInventoryLocalPath(`C:\`+path) || seen[strings.ToLower(path)] {
			continue
		}
		seen[strings.ToLower(path)] = true
		paths = append(paths, path)
	}
	return paths
}

func windowsInventoryLocalPath(path string) bool {
	if len(path) < 4 || !((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) || path[1:3] != `:\` || strings.ContainsAny(path, "/\x00") {
		return false
	}
	for _, part := range strings.Split(path[3:], `\`) {
		if part == "" || part == "." || part == ".." || strings.TrimRight(part, " .") != part || strings.ContainsAny(part, `:<>"|?*`) {
			return false
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		deviceNumber := strings.TrimPrefix(strings.TrimPrefix(base, "COM"), "LPT")
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || (deviceNumber != base && strings.Contains("|1|2|3|4|5|6|7|8|9|¹|²|³|", "|"+deviceNumber+"|")) {
			return false
		}
	}
	return true
}

type boundedWindowsDiscovery struct{ bytes.Buffer }

func (b *boundedWindowsDiscovery) Write(data []byte) (int, error) {
	if b.Len()+len(data) > maxWindowsDiscoveryOutput {
		return 0, errors.New("application metadata exceeds limit")
	}
	return b.Buffer.Write(data)
}
