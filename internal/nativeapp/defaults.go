package nativeapp

import (
	_ "embed"
	"encoding/json"
)

// Exact raw inherited defaults selected by ConfigLevel=10 in the reviewed
// v1.18.8 Templates.ini (Git blob aa2453a0eef7fa9b4ae797479dfe7c6c1e1c953a).
// Query with NO_EXPAND only: global inheritance and templates remain enabled.
//
// The stock explorer.exe,y selector is inert without any BreakoutDocument:
// core/dll/sh.c SH32_BreakoutDocument checks that separate matching list before
// requesting host execution. The verifier rejects every such trigger and any
// change/addition to these baseline values. It does not accept arbitrary keys.
//
//go:embed data/sandboxie-defaults-5.73.8.json
var defaultsJSON []byte
var stockDefaults = func() map[string][]string {
	var values map[string][]string
	if err := json.Unmarshal(defaultsJSON, &values); err != nil {
		panic("invalid compiled Sandboxie defaults")
	}
	return values
}()
