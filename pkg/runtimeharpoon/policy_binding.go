package runtimeharpoon

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
)

const headerRuleInvocationPrefix = "hr1:"

func isPolicyBoundTemplateLabel(label string) bool {
	parts := strings.Split(label, ":")
	if len(parts) != 3 || parts[0] != "hr1" || len(parts[1]) != sha256.Size*2 || !labelPattern.MatchString(parts[2]) {
		return false
	}
	_, err := hex.DecodeString(parts[1])
	return err == nil
}

// WithPolicyBinding scopes rich-header invocation labels to a tunnel and its
// resolved runtime credential. Identically configured replicas can execute the
// same invocation; different policy or credential revisions reject it.
func WithPolicyBinding(controlPlane *runtimeconfig.ControlPlaneConfig) ServerOption {
	var key []byte
	if controlPlane != nil && controlPlane.APIKey != "" && controlPlane.TunnelID.String() != "" {
		mac := hmac.New(sha256.New, []byte(controlPlane.APIKey))
		writeDigestFrame(mac, "tunnel-client/harpoon/header-rules/key/v1")
		writeDigestFrame(mac, controlPlane.TunnelID.String())
		key = mac.Sum(nil)
	}
	return func(options *serverOptions) {
		if options != nil && len(key) > 0 {
			options.policyBindingKey = append([]byte(nil), key...)
		}
	}
}

func (s *Server) templateInvocationLabel(target Target) string {
	if target.template == nil || !target.template.HasRichHeaderRules() {
		return target.Label
	}
	mac := hmac.New(sha256.New, s.policyBindingKey)
	writeDigestFrame(mac, "tunnel-client/harpoon/header-rules/invocation/v1")
	writeDigestFrame(mac, target.Label)
	writeDigestFrame(mac, target.template.PolicyDigest())
	return headerRuleInvocationPrefix + hex.EncodeToString(mac.Sum(nil)) + ":" + target.Label
}

func (s *Server) lookupTemplateInvocation(label string) (Target, bool) {
	if strings.HasPrefix(label, headerRuleInvocationPrefix) {
		parts := strings.Split(label, ":")
		if !isPolicyBoundTemplateLabel(label) {
			return Target{}, false
		}
		target, ok := s.registry.Lookup(parts[2])
		if !ok || target.template == nil || !target.template.HasRichHeaderRules() ||
			!hmac.Equal([]byte(label), []byte(s.templateInvocationLabel(target))) {
			return Target{}, false
		}
		return target, true
	}
	target, ok := s.registry.Lookup(label)
	if !ok || target.template == nil || target.template.HasRichHeaderRules() {
		return Target{}, false
	}
	return target, true
}

// Read every top-level argument pair so escaped spellings and overwritten
// duplicate labels cannot bypass strict template decoding. Nested values are
// consumed as values, never mistaken for subsequent object keys.
func containsBoundInvocationLabel(raw json.RawMessage) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return false
	}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return false
		}
		var label string
		if key == "label" && json.Unmarshal(value, &label) == nil && strings.HasPrefix(label, headerRuleInvocationPrefix) {
			return true
		}
	}
	return false
}
