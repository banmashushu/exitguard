package enforce

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

type ruleCondition struct {
	Field    string
	NotEqual bool
	Value    uint32
}
type denyRule struct {
	Key        [16]byte
	Program    string
	Family     int
	Inbound    bool
	Conditions []ruleCondition
	Index      int
}

const wfpOwner = "ExitGuard.WFP.v1"

type nativeRuleMetadata struct {
	Owner      string `json:"owner"`
	PolicyHash string `json:"policyHash"`
	Program    string `json:"program"`
	Rule       int    `json:"rule"`
}

func stableRuleKey(hash, program string, index int) [16]byte {
	digest := sha256.Sum256([]byte(fmt.Sprintf("ExitGuard.WFP.v1\n%s\n%d:%s\n%d", hash, len(program), program, index)))
	return [16]byte(digest[:16])
}

func encodeRuleMetadata(rule denyRule, hash string) []byte {
	data, _ := json.Marshal(nativeRuleMetadata{Owner: wfpOwner, PolicyHash: hash, Program: rule.Program, Rule: rule.Index})
	return data
}

func metadataOwnsRule(data []byte, key [16]byte) bool {
	if len(data) > 32768 {
		return false
	}
	var metadata nativeRuleMetadata
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&metadata) != nil || decoder.Decode(new(any)) != io.EOF || metadata.Owner != wfpOwner || metadata.Rule < 0 || metadata.Rule > 5 || len(metadata.PolicyHash) != 64 {
		return false
	}
	if _, err := hex.DecodeString(metadata.PolicyHash); err != nil {
		return false
	}
	if _, err := normalize(Policy{Port: 1, Programs: []string{metadata.Program}}); err != nil {
		return false
	}
	return key == stableRuleKey(metadata.PolicyHash, metadata.Program, metadata.Rule)
}

// The allowed set is TCP AND 127.0.0.1 AND guard-port. Its complement is
// expressed as three disjoint-purpose BLOCK filters. No PERMIT filter competes
// with a broad BLOCK filter, and changing sublayer precedence cannot open it.
func windowsRules(p Policy) []denyRule {
	var out []denyRule
	for _, program := range uniqueSorted(p.Programs) {
		for index, rule := range []denyRule{
			{Family: 4, Conditions: []ruleCondition{{Field: "address", NotEqual: true, Value: 0x7f000001}}},
			{Family: 4, Conditions: []ruleCondition{{Field: "port", NotEqual: true, Value: uint32(p.Port)}}},
			{Family: 4, Conditions: []ruleCondition{{Field: "protocol", NotEqual: true, Value: 6}}},
			{Family: 6},
			{Family: 4, Inbound: true},
			{Family: 6, Inbound: true},
		} {
			rule.Program = program
			rule.Index = index
			rule.Key = stableRuleKey(Hash(p), program, index)
			out = append(out, rule)
		}
	}
	return out
}
