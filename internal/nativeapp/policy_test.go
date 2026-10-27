package nativeapp

import (
	"bytes"
	"strings"
	"testing"
)

// Removing the broad deny, or accepting an inherited allow, must break this test.
func TestOwnedPolicyRejectsInheritedOverrides(t *testing.T) {
	p, err := Policy("chrome")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEffective(p); err != nil {
		t.Fatal(err)
	}
	for key, values := range map[string][]string{
		"NetworkAccess": {"*,Block", "*,Allow;Address=127.0.0.1;Port=17890;Protocol=TCP", "chrome.exe,Allow"},
		"Template":      {"WebBrowser"}, "OpenIpcPath": {"*"}, "BreakoutProcess": {"*"},
		"AllowNetworkAccess": {"y", "chrome.exe,y"}, "NoSecurityIsolation": {"y"},
		"ClosedIpcPath": {`\RPC Control\Other`}, "UnknownRelaxation": {"y"},
	} {
		t.Run(key, func(t *testing.T) {
			got := clone(p)
			got[key] = values
			if VerifyEffective(got) == nil {
				t.Fatal("accepted changed effective policy")
			}
		})
	}
	delete(p, "NetworkAccess")
	if VerifyEffective(p) == nil {
		t.Fatal("accepted absent deny")
	}
}

func TestSetupPreservesVendorBytesAndRejectsExistingOwnedBox(t *testing.T) {
	old := []byte("[GlobalSettings]\r\nNetworkEnableWFP=y\r\n\r\n[Existing]\r\nNetworkAccess=*,Allow\r\n")
	result, err := AppendOwnedBoxes(old)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(result, old) {
		t.Fatal("changed vendor configuration")
	}
	if !bytes.Contains(result, []byte("[ExitGuard_Claude]")) {
		t.Fatal("owned group absent")
	}
	if _, err := AppendOwnedBoxes(result); err == nil {
		t.Fatal("overwrote existing owned boxes")
	}
	if _, err := AppendOwnedBoxes([]byte("[GlobalSettings]\nNetworkEnableWFP=n\n")); err == nil {
		t.Fatal("silently enabled global WFP")
	}
	if _, err := AppendOwnedBoxes([]byte("[GlobalSettings]\nNetworkEnableWFP=y\nInclude=other.ini\n")); err == nil {
		t.Fatal("accepted unreviewed include")
	}
}

func TestTargetMappingAndWindowsPathInjection(t *testing.T) {
	for target, base := range map[string]string{"chrome": "chrome.exe", "edge": "msedge.exe", "claude": "Claude.exe"} {
		plan, err := Command(target, `C:\Program Files\Vendor\`+base, `C:\Users\Alice\AppData\Local\ExitGuard\NativeProfiles\`+target)
		if err != nil {
			t.Fatal(err)
		}
		if plan.Box != "ExitGuard_"+strings.ToUpper(target[:1])+target[1:] {
			t.Fatal(plan.Box)
		}
		if plan.Args[0] != "/box:"+plan.Box || plan.Args[1] != `C:\Program Files\Vendor\`+base {
			t.Fatal(plan.Args)
		}
		if strings.Contains(strings.Join(plan.Args, " "), "password") {
			t.Fatal("credential in command")
		}
	}
	for _, path := range []string{`chrome.exe`, `\\host\share\chrome.exe`, `C:\a\..\chrome.exe`, `C:\x\chrome.exe:stream`, `C:\x\chrome.exe" /box:DefaultBox`, "C:\\x\\chrome.exe\nBreakoutProcess=*", `C:\%USER%\chrome.exe`, `C:\x\other.exe`} {
		if _, err := Command("chrome", path, `C:\Users\Alice\NativeProfiles\chrome`); err == nil {
			t.Fatalf("accepted %q", path)
		}
	}
	if _, err := Command("unknown", `C:\x\chrome.exe`, `C:\profiles`); err == nil {
		t.Fatal("accepted arbitrary target")
	}
}

func clone(p map[string][]string) map[string][]string {
	q := map[string][]string{}
	for k, v := range p {
		q[k] = append([]string{}, v...)
	}
	return q
}

func TestStockEffectiveTemplatesPassButGlobalPDFBreakoutFails(t *testing.T) {
	p, _ := Policy("edge")
	for k, v := range stockDefaults {
		p[k] = append([]string{}, v...)
	}
	p["NetworkEnableWFP"] = []string{"y"}
	if err := VerifyEffective(p); err != nil {
		t.Fatal("stock released effective defaults must support preview:", err)
	}
	p["BreakoutDocument"] = []string{"*.pdf"}
	if VerifyEffective(p) == nil {
		t.Fatal("stock explorer selector became an active global document breakout")
	}
	delete(p, "BreakoutDocument")
	p["OpenIpcPath"] = append(p["OpenIpcPath"], `\RPC Control\*`)
	if VerifyEffective(p) == nil {
		t.Fatal("accepted non-stock IPC relaxation")
	}
}
