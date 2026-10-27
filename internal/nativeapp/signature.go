package nativeapp

// Publishers were read from signed v1.18.8/5.73.8 official release binaries
// without executing them. This identity predicate does NOT substitute for
// Windows Authenticode chain validation (Valid must be observed on Windows).
func acceptSignature(evidence SignatureEvidence, kind string) bool {
	if !evidence.Valid {
		return false
	}
	switch kind {
	case "runtime":
		return evidence.Publisher == "NOVASYNC LABS PTE. LTD." && evidence.Thumbprint == "16FB9B0FB8CDDB8D2CCF1F4B4ABEEA6FE793C88E" && (evidence.Version == RuntimeVersion || evidence.Version == RuntimeVersion+".0") && evidence.Product == "Sandboxie"
	case "driver":
		return evidence.Publisher == "Microsoft Windows Hardware Compatibility Publisher" && evidence.Thumbprint == "6022340C9F4CB00307DF8DB036D392ADAC766212" && (evidence.Version == RuntimeVersion || evidence.Version == RuntimeVersion+".0") && evidence.Product == "Sandboxie"
	case "chrome":
		return evidence.Publisher == "Google LLC"
	case "edge":
		return evidence.Publisher == "Microsoft Corporation"
	case "claude":
		return evidence.Publisher == "Anthropic, PBC" || evidence.Publisher == "Anthropic PBC"
	}
	return false
}
