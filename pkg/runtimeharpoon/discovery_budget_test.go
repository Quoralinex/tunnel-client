package runtimeharpoon

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	validateschema "github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
)

func largeDiscoveryTemplate() *runtimeconfig.HarpoonTargetTemplate {
	cfg := templateTestConfig()
	parameter := cfg.Parameters["resourceId"]
	parameter.Examples = []string{"item-123"}
	cfg.Parameters["resourceId"] = parameter
	cfg.Headers = map[string]string{"Authorization": "Bearer private-fixed-value"}
	for i := range 8 {
		var values []string
		for j := range 64 {
			values = append(values, fmt.Sprintf("%03d%s", j, strings.Repeat("x", 125)))
		}
		cfg.HeaderRules = append(cfg.HeaderRules, runtimeconfig.HarpoonHeaderRule{
			Name: fmt.Sprintf("X-Choice-%d", i), Description: `Public "choice" <metadata>`,
			ForwardAs:  fmt.Sprintf("X-Private-Destination-%d", i),
			Validation: &runtimeconfig.HarpoonHeaderValidation{Enum: values},
		})
	}
	return cfg
}

func TestTemplateDiscoveryBudgetBoundsCompleteMCPResults(t *testing.T) {
	t.Parallel()
	logger := runtimeRegistryTestLogger()
	registry, err := NewRegistry(logger, false, nil)
	require.NoError(t, err)
	var rejected bool
	for i := range 32 {
		beforeCount, beforeBytes, beforeState := registry.Count(), registry.discoveryBytes, registry.stateCh
		beforeDigest := mustStartupCatalogDigest(t, registry, "key", "tunnel")
		err := registry.RegisterTarget(Target{
			Label: fmt.Sprintf("large-%d", i), Template: largeDiscoveryTemplate(),
			Description: strings.Repeat("escaped \"quotes\" \\ <>&\n é 😀 ", 128),
		})
		if err == nil {
			continue
		}
		require.ErrorContains(t, err, "512 KiB catalog budget")
		require.NotContains(t, err.Error(), "private-fixed-value")
		require.NotContains(t, err.Error(), "X-Private-Destination")
		require.Equal(t, beforeCount, registry.Count())
		require.Equal(t, beforeBytes, registry.discoveryBytes)
		require.Equal(t, beforeState, registry.stateCh)
		require.Equal(t, beforeDigest, mustStartupCatalogDigest(t, registry, "key", "tunnel"))
		_, found := registry.Lookup(fmt.Sprintf("large-%d", i))
		require.False(t, found)
		rejected = true
		break
	}
	require.True(t, rejected, "individually valid large enums must not grow discovery without a bound")
	require.GreaterOrEqual(t, registry.Count(), 2)
	// A failed registration must not consume space that a small target needs.
	require.NoError(t, registry.RegisterTarget(Target{Label: "small", Template: templateTestConfig()}))
	rebuilt, err := NewRegistry(logger, false, registry.Targets())
	require.NoError(t, err)
	require.Equal(t, registry.discoveryBytes, rebuilt.discoveryBytes)

	server, err := NewServer(&runtimeconfig.HarpoonConfig{MaxResponseBytes: math.MaxInt}, registry, logger)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.MCPServer().Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = serverSession.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "discovery-budget-test", Version: "test"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientSession.Close() })
	tools, err := clientSession.ListTools(ctx, nil)
	require.NoError(t, err)
	targets, err := clientSession.CallTool(ctx, &mcp.CallToolParams{Name: "list_targets", Arguments: map[string]any{}})
	require.NoError(t, err)
	require.False(t, targets.IsError)
	require.NotNil(t, targets.StructuredContent)
	require.NotEmpty(t, targets.Content)
	for name, result := range map[string]any{"tools/list": tools, "list_targets": targets} {
		// Exercise actual SDK results, including text/structured duplication,
		// then include JSON-RPC and tunnel response envelopes in the bound.
		encoded, err := json.Marshal(map[string]any{
			"request_id": "discovery-budget-test", "resp_json": map[string]any{
				"jsonrpc": "2.0", "id": 1, "result": result,
			}, "metadata": map[string]any{"channel": "harpoon"},
		})
		require.NoError(t, err)
		require.LessOrEqual(t, len(encoded), maxTemplateDiscoveryBytes, name)
		require.Contains(t, string(encoded), "Public")
		require.Contains(t, string(encoded), "X-Choice-0")
		require.NotContains(t, string(encoded), "X-Private-Destination")
		require.NotContains(t, string(encoded), "private-fixed-value")
	}
}

func TestTemplateDiscoveryBudgetPreservesExactOnlyCatalogs(t *testing.T) {
	t.Parallel()
	for _, templateFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("template_first_%t", templateFirst), func(t *testing.T) {
			registry, err := NewRegistry(runtimeRegistryTestLogger(), false, nil)
			require.NoError(t, err)
			template := Target{Label: "template", Template: richHeaderTestConfig()}
			// Legal existing exact metadata exceeds the new template budget.
			exact := Target{Label: "exact", BaseURL: runtimeRegistryTestURL(t, "https://exact.example"), Description: strings.Repeat("x", maxTemplateDiscoveryBytes)}
			if templateFirst {
				require.NoError(t, registry.RegisterTarget(template))
				require.ErrorContains(t, registry.RegisterTarget(exact), "catalog budget")
			} else {
				require.NoError(t, registry.RegisterTarget(exact), "exact-only compatibility")
				require.ErrorContains(t, registry.RegisterTarget(template), "catalog budget")
			}
			require.Equal(t, 1, registry.Count())
		})
	}
}

func largeLegacyDiscoveryTemplate() *runtimeconfig.HarpoonTargetTemplate {
	cfg := templateTestConfig()
	cfg.AllowedHeaders = []string{"X-Request-Tag"}
	cfg.Query = make(map[string]string)
	cfg.Parameters = make(map[string]runtimeconfig.HarpoonTemplateParameter)
	for i := range 16 {
		name := fmt.Sprintf("parameter%d", i)
		if i == 0 {
			name = "resourceId"
		} else {
			cfg.Query[name] = "{" + name + "}"
		}
		var values []string
		for j := range 64 {
			values = append(values, fmt.Sprintf("%03d%s", j, strings.Repeat("x", 125)))
		}
		cfg.Parameters[name] = runtimeconfig.HarpoonTemplateParameter{
			Type: "string", Required: true, MaxLength: 128, Enum: values,
		}
	}
	return cfg
}

func TestTemplateDiscoveryBudgetPreservesLargeLegacyCatalogs(t *testing.T) {
	t.Parallel()
	logger := runtimeRegistryTestLogger()
	registry, err := NewRegistry(logger, false, nil)
	require.NoError(t, err)
	for i := range 3 {
		require.NoError(t, registry.RegisterTarget(Target{
			Label: fmt.Sprintf("legacy-%d", i), Template: largeLegacyDiscoveryTemplate(),
		}))
	}
	require.Greater(t, registry.discoveryBytes, maxTemplateCatalogBytes)
	server, err := NewServer(&runtimeconfig.HarpoonConfig{}, registry, logger)
	require.NoError(t, err)
	schema := server.callTargetInputSchema()
	require.Len(t, schema.OneOf, 2, "legacy templates retain one shared generic branch")
	actual, err := json.Marshal(schema.OneOf[1])
	require.NoError(t, err)
	legacy, err := json.Marshal(server.templateCallInputSchema())
	require.NoError(t, err)
	require.Equal(t, legacy, actual)
	complete, err := json.Marshal(schema)
	require.NoError(t, err)
	require.Less(t, len(complete), 16*1024, "legacy tools/list size must not grow with public parameter enums")
	// The same catalog cannot subsequently opt into structured rules while
	// its full list_targets result exceeds the new budget.
	require.ErrorContains(t, registry.RegisterTarget(Target{Label: "rich", Template: richHeaderTestConfig()}), "catalog budget")
	require.Equal(t, 3, registry.Count())
}

func TestTemplateDiscoveryBudgetCountsLegacyTemplatesInRichCatalogs(t *testing.T) {
	t.Parallel()
	for _, richFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("rich_first_%t", richFirst), func(t *testing.T) {
			registry, err := NewRegistry(runtimeRegistryTestLogger(), false, nil)
			require.NoError(t, err)
			rich := Target{Label: "rich", Template: richHeaderTestConfig()}
			legacy := Target{Label: "legacy", Template: largeLegacyDiscoveryTemplate()}
			if richFirst {
				require.NoError(t, registry.RegisterTarget(rich))
				require.ErrorContains(t, registry.RegisterTarget(legacy), "catalog budget")
			} else {
				require.NoError(t, registry.RegisterTarget(legacy))
				require.ErrorContains(t, registry.RegisterTarget(rich), "catalog budget")
			}
			require.Equal(t, 1, registry.Count())
		})
	}
}

func TestTemplateDiscoveryMixedBranchesAreDisjoint(t *testing.T) {
	t.Parallel()
	logger := runtimeRegistryTestLogger()
	legacy := templateTestConfig()
	legacy.AllowedHeaders = []string{"X-Request-Tag"}
	registry, err := NewRegistry(logger, false, []Target{
		{Label: "legacy", Template: legacy},
		{Label: "rich", Template: richHeaderTestConfig()},
	})
	require.NoError(t, err)
	server, err := NewServer(&runtimeconfig.HarpoonConfig{}, registry, logger)
	require.NoError(t, err)
	inputSchema := server.callTargetInputSchema()
	require.Len(t, inputSchema.OneOf, 3)
	encoded, err := json.Marshal(inputSchema)
	require.NoError(t, err)
	var schema validateschema.Schema
	require.NoError(t, json.Unmarshal(encoded, &schema))
	resolved, err := schema.Resolve(nil)
	require.NoError(t, err)
	legacyArgs := map[string]any{
		"label": "legacy", "parameters": map[string]any{"resourceId": "one"},
		"headers": map[string]any{"x-request-tag": "legacy-value"},
	}
	require.NoError(t, resolved.Validate(legacyArgs))
	richTarget, found := registry.Lookup("rich")
	require.True(t, found)
	richArgs := map[string]any{
		"label": server.templateInvocationLabel(richTarget), "parameters": map[string]any{"resourceId": "one"},
		"headers": map[string]any{"Authorization": "Bearer caller-value", "X-Trace": "req-123"},
	}
	require.NoError(t, resolved.Validate(richArgs), "a rich invocation must match exactly one branch")
	delete(richArgs, "headers")
	require.Error(t, resolved.Validate(richArgs), "the generic legacy branch must not bypass rich required headers")
}

func TestTemplateDiscoveryBudgetProtectsRegisteredMetadata(t *testing.T) {
	t.Parallel()
	registry, err := NewRegistry(runtimeRegistryTestLogger(), false, []Target{
		{Label: "template", Template: templateTestConfig(), Tags: []string{"original"}},
		{Label: "exact", BaseURL: runtimeRegistryTestURL(t, "https://exact.example"), Tags: []string{"original"}},
	})
	require.NoError(t, err)
	lookup, found := registry.Lookup("template")
	require.True(t, found)
	waited, err := registry.WaitForTarget(context.Background(), "template")
	require.NoError(t, err)
	exact, found := registry.TargetForURL(runtimeRegistryTestURL(t, "https://exact.example"))
	require.True(t, found)
	for _, target := range append(registry.Targets(), lookup, waited, exact) {
		target.Tags[0] = strings.Repeat("x", maxTemplateDiscoveryBytes)
	}
	for _, target := range registry.Targets() {
		require.Equal(t, []string{"original"}, target.Tags)
	}
}
