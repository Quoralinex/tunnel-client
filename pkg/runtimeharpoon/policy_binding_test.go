package runtimeharpoon

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
)

func policyBindingTestConfig() *runtimeconfig.HarpoonTargetTemplate {
	cfg := templateTestConfig()
	cfg.HeaderRules = []runtimeconfig.HarpoonHeaderRule{{
		Name: "X-Trace-Id", Description: "Request correlation identifier", ForwardAs: "X-Internal-Correlation",
	}}
	return cfg
}

func policyBindingTestServer(t *testing.T, cfg *runtimeconfig.HarpoonTargetTemplate, key, tunnel string) *Server {
	t.Helper()
	logger := runtimeRegistryTestLogger()
	registry, err := NewRegistry(logger, false, []Target{{Label: "resource", Template: cfg}})
	require.NoError(t, err)
	server, err := NewServer(&runtimeconfig.HarpoonConfig{MaxResponseBytes: 2048}, registry, logger,
		WithPolicyBinding(catalogDigestControlPlane(key, tunnel)))
	require.NoError(t, err)
	return server
}

func TestHeaderRuleInvocationBindingAcrossReplicasAndPolicyChanges(t *testing.T) {
	t.Parallel()
	first := policyBindingTestServer(t, policyBindingTestConfig(), "runtime-key", "tunnel_scope")
	target, ok := first.registry.Lookup("resource")
	require.True(t, ok)
	label := first.templateInvocationLabel(target)
	require.True(t, isPolicyBoundTemplateLabel(label))
	require.False(t, labelPattern.MatchString(label), "historical executors cannot register a bound label")
	require.NotContains(t, label, "X-Internal-Correlation")

	identical := policyBindingTestServer(t, policyBindingTestConfig(), "runtime-key", "tunnel_scope")
	_, ok = identical.lookupTemplateInvocation(label)
	require.True(t, ok, "equivalent replicas must share the invocation contract")
	_, ok = first.lookupTemplateInvocation("resource")
	require.False(t, ok, "rich targets must reject unbound invocations")

	for _, change := range []struct {
		name  string
		apply func(*runtimeconfig.HarpoonTargetTemplate)
	}{
		{"destination", func(c *runtimeconfig.HarpoonTargetTemplate) { c.Origin = "https://other.example" }},
		{"path", func(c *runtimeconfig.HarpoonTargetTemplate) { c.PathTemplate = "/other/{resourceId}" }},
		{"rename", func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[0].ForwardAs = "X-Other-Correlation" }},
		{"required", func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[0].Required = true }},
		{"validation", func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.HeaderRules[0].Validation = &runtimeconfig.HarpoonHeaderValidation{Pattern: "[a-z]+"}
		}},
		{"fixed credential", func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.Headers = map[string]string{"Authorization": "Bearer private-static-token"}
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			t.Parallel()
			cfg := policyBindingTestConfig()
			change.apply(cfg)
			changed := policyBindingTestServer(t, cfg, "runtime-key", "tunnel_scope")
			_, found := changed.lookupTemplateInvocation(label)
			require.False(t, found, "an invocation for another private policy must fail closed")
		})
	}
	for _, scope := range []struct{ key, tunnel string }{{"other-key", "tunnel_scope"}, {"runtime-key", "tunnel_other"}} {
		server := policyBindingTestServer(t, policyBindingTestConfig(), scope.key, scope.tunnel)
		_, found := server.lookupTemplateInvocation(label)
		require.False(t, found)
	}
	legacy := policyBindingTestServer(t, templateTestConfig(), "runtime-key", "tunnel_scope")
	_, ok = legacy.lookupTemplateInvocation(label)
	require.False(t, ok, "an old policy for the same logical label must reject a rich invocation")
	_, ok = legacy.lookupTemplateInvocation("resource")
	require.True(t, ok, "legacy invocation behavior remains available for legacy targets")
}

func TestBoundInvocationDuplicateLabelCannotFallBackToExact(t *testing.T) {
	t.Parallel()
	logger := runtimeRegistryTestLogger()
	registry, err := NewRegistry(logger, false, []Target{{Label: "exact", BaseURL: runtimeRegistryTestURL(t, "https://exact.example/")}})
	require.NoError(t, err)
	calls := 0
	server, err := NewServer(&runtimeconfig.HarpoonConfig{MaxResponseBytes: 2048}, registry, logger,
		WithHTTPTransport(templateServerTransport(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header)}, nil
		})))
	require.NoError(t, err)
	for _, raw := range []string{
		`{"label":"hr1:revision:resource","label":"exact","method":"GET"}`,
		`{"labe\u006c":"\u0068r1:revision:resource","label":"exact","method":"GET"}`,
		`{"method":"label","label":"hr1:revision:resource","label":"exact","method":"GET"}`,
	} {
		var args map[string]any
		require.NoError(t, json.Unmarshal([]byte(raw), &args))
		result, _, err := server.callUnifiedTargetHandler()(context.Background(), &mcp.CallToolRequest{
			Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage(raw)},
		}, args)
		require.NoError(t, err)
		require.True(t, result.IsError)
	}
	require.Zero(t, calls, "overwritten bound labels must never reach the exact target")
}
