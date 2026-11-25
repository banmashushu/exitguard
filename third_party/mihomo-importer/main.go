// SPDX-License-Identifier: GPL-3.0-only
// This executable intentionally stays outside ExitGuard's application module.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/metacubex/mihomo/common/convert"
	nativeLog "github.com/metacubex/mihomo/log"
	"github.com/sirupsen/logrus"
)

const (
	protocolVersion = 1
	coreVersion     = "v1.19.33"
	sourceCommit    = "3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8"
	maxLines        = 500
	maxSourceBytes  = 5 << 20
	maxWireBytes    = 32 << 20
	// An existing upstream-generated default, fixed to preserve import identity.
	stableUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.162 Safari/537.36"
)

type conversion struct {
	Config map[string]any `json:"config,omitempty"`
	Error  string         `json:"error,omitempty"`
}
type request struct {
	Version int      `json:"version"`
	Lines   []string `json:"lines"`
}
type response struct {
	Version      int          `json:"version"`
	CoreVersion  string       `json:"core_version"`
	SourceCommit string       `json:"source_commit"`
	Results      []conversion `json:"results"`
}

var quietOnce sync.Once

func quiet() {
	quietOnce.Do(func() { nativeLog.SetLevel(nativeLog.SILENT); logrus.SetOutput(io.Discard) })
}
func convertLine(line string) conversion { return convertLineWith(line, convert.ConvertsV2Ray) }
func convertLineWith(line string, convertNative func([]byte) ([]map[string]any, error)) (result conversion) {
	quiet()
	result.Error = "invalid_uri"
	defer func() {
		if recover() != nil {
			result = conversion{Error: "invalid_uri"}
		}
	}()
	if line == "" || !utf8.ValidString(line) || strings.IndexFunc(line, unicode.IsControl) >= 0 {
		return
	}
	nodes, err := convertNative([]byte(line))
	if err != nil || len(nodes) != 1 || len(nodes[0]) == 0 {
		return
	}
	node := nodes[0]
	// The native URI converter itself inserts this randomized header; URI fields
	// have no user-agent/header mapping. Keep every user pin/auth field intact.
	if network, _ := node["network"].(string); network == "ws" || network == "httpupgrade" {
		if opts, ok := node["ws-opts"].(map[string]any); ok {
			if headers, ok := opts["headers"].(map[string]any); ok {
				if _, generated := headers["User-Agent"]; generated {
					headers["User-Agent"] = stableUserAgent
				}
			}
		}
	}
	return conversion{Config: node}
}
func strictJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return errors.New("invalid_request")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return errors.New("invalid_request")
				}
				seen[s] = true
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid_request")
		}
		_, err = d.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("invalid_request")
	}
	return nil
}
func run(input io.Reader, output io.Writer) (code int) {
	quiet()
	code = 2
	defer func() {
		if recover() != nil {
			code = 2
		}
	}()
	data, err := io.ReadAll(io.LimitReader(input, maxWireBytes+1))
	if err != nil || len(data) > maxWireBytes || strictJSON(data) != nil {
		return
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var req request
	if d.Decode(&req) != nil || req.Version != protocolVersion || len(req.Lines) == 0 || len(req.Lines) > maxLines {
		return
	}
	total := 0
	for _, line := range req.Lines {
		total += len(line)
		if total > maxSourceBytes {
			return
		}
	}
	resp := response{Version: protocolVersion, CoreVersion: coreVersion, SourceCommit: sourceCommit, Results: make([]conversion, len(req.Lines))}
	for i, line := range req.Lines {
		resp.Results[i] = convertLine(line)
	}
	encoded, err := json.Marshal(resp)
	if err != nil || len(encoded) > maxWireBytes {
		return
	}
	if _, err = output.Write(encoded); err != nil {
		return
	}
	return 0
}
func main() {
	if len(os.Args) != 1 {
		os.Exit(2)
	}
	os.Exit(run(os.Stdin, os.Stdout))
}
