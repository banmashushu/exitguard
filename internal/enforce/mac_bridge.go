package enforce

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

func parseManagerProof(data []byte, hash string) (Proof, error) {
	var proof Proof
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return Proof{Reason: "invalid signed filter manager response"}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Proof{Reason: "extra signed filter manager response data"}, errors.New("filter manager returned more than one response")
	}
	if !proof.Active {
		return proof, errors.New(proof.Reason)
	}
	if hash == "" || proof.PolicyHash != hash {
		return Proof{Reason: "native filter policy does not match current configuration"}, errors.New("native filter policy hash mismatch")
	}
	return proof, nil
}
