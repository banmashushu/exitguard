package nativeapp

import "testing"

func TestRuntimeSignatureRequiresReviewedPublisherAndExactVersion(t *testing.T) {
	good := SignatureEvidence{File: "Start.exe", Valid: true, Publisher: "NOVASYNC LABS PTE. LTD.", Thumbprint: "16FB9B0FB8CDDB8D2CCF1F4B4ABEEA6FE793C88E", Version: "5.73.8", Product: "Sandboxie"}
	if !acceptSignature(good, "runtime") {
		t.Fatal("reviewed official signer/version rejected")
	}
	for _, bad := range []SignatureEvidence{
		{Valid: false, Publisher: good.Publisher, Version: good.Version, Product: good.Product},
		{Valid: true, Publisher: "prefix NOVASYNC LABS PTE. LTD. suffix", Version: good.Version, Product: good.Product},
		{Valid: true, Publisher: good.Publisher, Version: "5.73.80", Product: good.Product},
		{Valid: true, Publisher: good.Publisher, Version: good.Version, Product: "Other product"},
	} {
		if acceptSignature(bad, "runtime") {
			t.Fatal("accepted unreviewed runtime identity", bad)
		}
	}
	if !acceptSignature(SignatureEvidence{Valid: true, Publisher: "Microsoft Windows Hardware Compatibility Publisher", Thumbprint: "6022340C9F4CB00307DF8DB036D392ADAC766212", Version: "5.73.8", Product: "Sandboxie"}, "driver") {
		t.Fatal("reviewed driver publisher rejected")
	}
}
