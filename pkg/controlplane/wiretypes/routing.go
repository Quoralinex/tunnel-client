package wiretypes

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
)

const (
	ShardTokenHeader     = "X-Tunnel-Shard-Token"
	WrongClusterCode     = "wrong_cluster"
	MaxRoutingTokenBytes = 4096
	MaxPolicyRevision    = uint64(9007199254740991)
)

// RoutingCorrection is poll-only metadata. Tokens are opaque and must never
// replace the original shard token attached to a command.
type RoutingCorrection struct {
	ShardToken     string `json:"shard_token"`
	PolicyRevision uint64 `json:"policy_revision"`
}

var errInvalidRoutingCorrection = errors.New("invalid polling routing correction")

// ParseRoutingCorrection validates a 409 response's metadata. A different error
// code returns nil; callers must separately require HTTP 409. Unknown metadata
// is ignored. Errors deliberately contain no response data.
func ParseRoutingCorrection(header http.Header, body []byte) (*RoutingCorrection, error) {
	envelope, err := routingObject(body, "error")
	if err != nil {
		return nil, errInvalidRoutingCorrection
	}
	if _, present := envelope["error"]; !present {
		return nil, nil
	}
	metadata, err := routingObject(envelope["error"], "code", "policy_revision", "shard_token")
	if err != nil {
		return nil, errInvalidRoutingCorrection
	}
	var code string
	if err := json.Unmarshal(metadata["code"], &code); err != nil || code != WrongClusterCode {
		return nil, nil
	}
	values := header.Values(ShardTokenHeader)
	if len(values) != 1 || !validRoutingToken(values[0]) {
		return nil, errInvalidRoutingCorrection
	}
	token := values[0]
	if raw, present := metadata["shard_token"]; present {
		var bodyToken string
		if err := json.Unmarshal(raw, &bodyToken); err != nil || bodyToken != token {
			return nil, errInvalidRoutingCorrection
		}
	}
	rawRevision := metadata["policy_revision"]
	if len(rawRevision) == 0 || len(rawRevision) > 16 {
		return nil, errInvalidRoutingCorrection
	}
	for _, b := range rawRevision {
		if b < '0' || b > '9' {
			return nil, errInvalidRoutingCorrection
		}
	}
	revision, err := strconv.ParseUint(string(rawRevision), 10, 64)
	if err != nil || revision > MaxPolicyRevision {
		return nil, errInvalidRoutingCorrection
	}
	return &RoutingCorrection{ShardToken: token, PolicyRevision: revision}, nil
}

// Decode only exact protocol keys and reject duplicate known fields. Last-wins
// JSON decoding could otherwise hide conflicting token copies or synthesize a
// valid correction by merging two incomplete error objects.
func routingObject(body []byte, keys ...string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errInvalidRoutingCorrection
	}
	fields := make(map[string]json.RawMessage, len(keys))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, errInvalidRoutingCorrection
		}
		name, ok := token.(string)
		if !ok {
			return nil, errInvalidRoutingCorrection
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, errInvalidRoutingCorrection
		}
		for _, key := range keys {
			if name == key {
				if _, duplicate := fields[key]; duplicate {
					return nil, errInvalidRoutingCorrection
				}
				fields[key] = value
			}
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errInvalidRoutingCorrection
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errInvalidRoutingCorrection
	}
	return fields, nil
}

func validRoutingToken(token string) bool {
	if len(token) == 0 || len(token) > MaxRoutingTokenBytes {
		return false
	}
	for i := range len(token) {
		if token[i] < 0x21 || token[i] > 0x7e || token[i] == ',' {
			return false
		}
	}
	return true
}
