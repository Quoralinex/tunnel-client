package runtimeharpoon

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	validateschema "github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
	"github.com/openai/tunnel-client/pkg/version"
)

func richHeaderTestConfig() *runtimeconfig.HarpoonTargetTemplate {
	cfg := templateTestConfig()
	cfg.HeaderRules = []runtimeconfig.HarpoonHeaderRule{
		{Name: "Authorization", Description: "Complete caller bearer value", Credential: true, Required: true,
			Validation: &runtimeconfig.HarpoonHeaderValidation{Pattern: `^Bearer [A-Za-z0-9_-]+$`, MinLength: new(8), MaxLength: new(128)}},
		{Name: "X-Trace", Description: "Request correlation identifier", ForwardAs: "X-Private-Correlation", Required: true,
			Validation: &runtimeconfig.HarpoonHeaderValidation{Pattern: `^[a-z0-9-]+$`, MinLength: new(3), MaxLength: new(12)}},
		{Name: "X-Mode", Description: "Requested representation",
			Validation: &runtimeconfig.HarpoonHeaderValidation{Enum: []string{"summary", "full"}, MinLength: new(4), MaxLength: new(7)}},
	}
	return cfg
}

func richHeaderTestValues() map[string]string {
	return map[string]string{"Authorization": "Bearer caller-secret", "X-Trace": "req-123", "X-Mode": "full"}
}

func TestHeaderRulesCompileRejectsUnsafePolicies(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*runtimeconfig.HarpoonTargetTemplate){
		"missing description":    func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[1].Description = "" },
		"whitespace description": func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[1].Description = "   " },
		"control description":    func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[1].Description = "a\nb" },
		"too long description":   func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[1].Description = strings.Repeat("x", 1025) },
		"source reserved":        func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[1].Name = "Cookie" },
		"destination reserved": func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.HeaderRules[1].ForwardAs = "X-Openai-Actor-Authorization"
		},
		"source routing":             func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[1].Name = "X-Forwarded-Host" },
		"destination routing":        func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[1].ForwardAs = "X-Original-URL" },
		"source duplicate":           func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules = append(c.HeaderRules, c.HeaderRules[1]) },
		"case duplicate":             func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[2].Name = "x-trace" },
		"destination duplicate":      func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[2].ForwardAs = "x-private-correlation" },
		"source destination overlap": func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[2].Name = "x-private-correlation" },
		"source fixed collision":     func(c *runtimeconfig.HarpoonTargetTemplate) { c.Headers = map[string]string{"x-trace": "private"} },
		"destination fixed collision": func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.Headers = map[string]string{"x-private-correlation": "private"}
		},
		"credential opt in required":      func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[0].Credential = false },
		"credential pattern required":     func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[0].Validation.Pattern = "" },
		"credential lower bound required": func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[0].Validation.MinLength = nil },
		"credential upper bound required": func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[0].Validation.MaxLength = nil },
		"credential positive lower bound": func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.HeaderRules[0].Validation.MinLength = new(0)
		},
		"credential recognized name required": func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[0].Name = "X-Unrecognized" },
		"other credential blocked":            func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[0].Name = "X-AuthToken" },
		"credential destination opt in":       func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[1].ForwardAs = "X-API-Key" },
		"destination unsupported credential":  func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[0].ForwardAs = "X-Client-Secret" },
		"pattern lookaround":                  func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[1].Validation.Pattern = `a(?=b)` },
		"pattern backreference":               func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[1].Validation.Pattern = `(a)\1` },
		"pattern flag":                        func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[1].Validation.Pattern = `(?i)abc` },
		"pattern unicode":                     func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[1].Validation.Pattern = `é` },
		"pattern malformed":                   func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[1].Validation.Pattern = `[` },
		"pattern size": func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.HeaderRules[1].Validation.Pattern = strings.Repeat("a", 513)
		},
		"length inverted": func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.HeaderRules[1].Validation.MinLength = new(13)
		},
		"negative length": func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.HeaderRules[1].Validation.MinLength = new(-1)
		},
		"length too large": func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.HeaderRules[1].Validation.MaxLength = new(8193)
		},
		"enum control": func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[2].Validation.Enum = []string{"full\n"} },
		"enum empty":   func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[2].Validation.Enum = []string{} },
		"enum duplicate": func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.HeaderRules[2].Validation.Enum = []string{"full", "full"}
		},
		"enum outside length":  func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[2].Validation.Enum = []string{"a"} },
		"enum outside pattern": func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[1].Validation.Enum = []string{"UPPER"} },
		"legacy rich fields":   func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[1].Legacy = true },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := richHeaderTestConfig()
			mutate(cfg)
			_, err := CompileTargetTemplate(cfg)
			require.Error(t, err)
			for _, private := range []string{"private", "X-Private-Correlation", "X-Client-Secret"} {
				require.NotContains(t, err.Error(), private)
			}
		})
	}
}

func TestHeaderRulesCallerValidationAndRenaming(t *testing.T) {
	t.Parallel()
	policy, err := CompileTargetTemplate(richHeaderTestConfig())
	require.NoError(t, err)
	require.True(t, policy.HasRichHeaderRules())
	headers, err := policy.ValidateCallerHeaders(map[string]string{"authorization": "Bearer caller-secret", "x-trace": "req-123", "x-mode": "full"})
	require.NoError(t, err)
	require.Equal(t, "Bearer caller-secret", headers.Get("Authorization"))
	require.Equal(t, "req-123", headers.Get("X-Private-Correlation"))
	require.Empty(t, headers.Values("X-Trace"))
	for name, mutate := range map[string]func(map[string]string){
		"missing credential":      func(h map[string]string) { delete(h, "Authorization") },
		"missing required header": func(h map[string]string) { delete(h, "X-Trace") },
		"empty credential":        func(h map[string]string) { h["Authorization"] = "" },
		"credential pattern":      func(h map[string]string) { h["Authorization"] = "Basic caller-secret" },
		"unicode pattern":         func(h map[string]string) { h["X-Trace"] = "ééé" },
		"short":                   func(h map[string]string) { h["X-Trace"] = "ab" },
		"long":                    func(h map[string]string) { h["X-Trace"] = strings.Repeat("x", 13) },
		"pattern full match":      func(h map[string]string) { h["X-Trace"] = "ABCabc" },
		"enum":                    func(h map[string]string) { h["X-Mode"] = "other" },
		"newline":                 func(h map[string]string) { h["X-Trace"] = "abc\n" },
		"duplicate source case":   func(h map[string]string) { h["x-trace"] = "req-456" },
		"destination supplied":    func(h map[string]string) { h["X-Private-Correlation"] = "req-456" },
		"unknown":                 func(h map[string]string) { h["X-Other"] = "value" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			values := richHeaderTestValues()
			mutate(values)
			_, err := policy.ValidateCallerHeaders(values)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "caller-secret")
			require.NotContains(t, err.Error(), "X-Private-Correlation")
		})
	}
}

func TestHeaderRulesLegacyAndUnicodeSemantics(t *testing.T) {
	t.Parallel()
	for _, canonical := range []bool{false, true} {
		cfg := templateTestConfig()
		if canonical {
			cfg.HeaderRules = []runtimeconfig.HarpoonHeaderRule{{Name: "X-Tag", Legacy: true}}
		} else {
			cfg.AllowedHeaders = []string{"X-Tag"}
		}
		policy, err := CompileTargetTemplate(cfg)
		require.NoError(t, err)
		require.False(t, policy.HasRichHeaderRules())
		for _, value := range []string{"", "café", "🙂"} {
			headers, err := policy.ValidateCallerHeaders(map[string]string{"x-tag": value})
			require.NoError(t, err)
			require.Equal(t, value, headers.Get("X-Tag"))
		}
		_, err = policy.ValidateCallerHeaders(nil)
		require.NoError(t, err)
	}
	cfg := templateTestConfig()
	cfg.HeaderRules = []runtimeconfig.HarpoonHeaderRule{{Name: "X-Tag", Description: "Unicode character pair", Validation: &runtimeconfig.HarpoonHeaderValidation{MinLength: new(2), MaxLength: new(2)}}}
	policy, err := CompileTargetTemplate(cfg)
	require.NoError(t, err)
	_, err = policy.ValidateCallerHeaders(map[string]string{"X-Tag": "🙂é"})
	require.NoError(t, err)
	_, err = policy.ValidateCallerHeaders(map[string]string{"X-Tag": "é"})
	require.Error(t, err)
	cfg.HeaderRules = []runtimeconfig.HarpoonHeaderRule{{Name: "Authorization", Legacy: true}}
	_, err = CompileTargetTemplate(cfg)
	require.Error(t, err)
}

func TestHeaderRulesSupportedCredentialDestination(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"Authorization", "X-API-Key", "API-Key"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := templateTestConfig()
			cfg.HeaderRules = []runtimeconfig.HarpoonHeaderRule{{Name: "X-Provided", ForwardAs: name, Description: "Per-call credential", Credential: true, Required: true, Validation: &runtimeconfig.HarpoonHeaderValidation{Pattern: `[a-z-]+`, MinLength: new(1), MaxLength: new(32)}}}
			policy, err := CompileTargetTemplate(cfg)
			require.NoError(t, err)
			headers, err := policy.ValidateCallerHeaders(map[string]string{"X-Provided": "caller-secret"})
			require.NoError(t, err)
			require.Equal(t, "caller-secret", headers.Get(name))
			require.Empty(t, headers.Values("X-Provided"))
		})
	}
}

func TestHeaderRulesOutboundBoundaryRechecksRichRules(t *testing.T) {
	t.Parallel()
	policy, err := CompileTargetTemplate(richHeaderTestConfig())
	require.NoError(t, err)
	parameters := map[string]any{"resourceId": "one"}
	resolved, err := policy.Render(parameters)
	require.NoError(t, err)
	newRequest := func() *http.Request {
		req, err := http.NewRequest(http.MethodGet, resolved.String(), nil)
		require.NoError(t, err)
		req.Header, err = policy.ValidateCallerHeaders(richHeaderTestValues())
		require.NoError(t, err)
		req.Header.Set("User-Agent", version.UserAgent)
		return req
	}
	require.NoError(t, policy.ValidateRequest(newRequest(), parameters))
	for name, mutate := range map[string]func(*http.Request){
		"required removed":         func(r *http.Request) { r.Header.Del("Authorization") },
		"renamed required removed": func(r *http.Request) { r.Header.Del("X-Private-Correlation") },
		"invalid credential":       func(r *http.Request) { r.Header.Set("Authorization", "Basic caller-secret") },
		"renamed validation":       func(r *http.Request) { r.Header.Set("X-Private-Correlation", "invalid value") },
		"enum bypass":              func(r *http.Request) { r.Header.Set("X-Mode", "other") },
		"source injected":          func(r *http.Request) { r.Header.Set("X-Trace", "req-123") },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			calls := 0
			transport := templateRoundTripper{policy: policy, parameters: parameters, base: templateServerTransport(func(*http.Request) (*http.Response, error) { calls++; return nil, nil })}
			req := newRequest()
			mutate(req)
			_, err := transport.RoundTrip(req)
			require.Error(t, err)
			require.Zero(t, calls)
		})
	}
}

func TestHeaderRulesPolicyDigestAndDefensiveCopy(t *testing.T) {
	t.Parallel()
	cfg := richHeaderTestConfig()
	original, err := CompileTargetTemplate(cfg)
	require.NoError(t, err)
	for name, mutate := range map[string]func(*runtimeconfig.HarpoonTargetTemplate){
		"description": func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.HeaderRules[1].Description = "Different public description"
		},
		"destination": func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[1].ForwardAs = "X-Other-Private" },
		"required":    func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[1].Required = false },
		"pattern":     func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[1].Validation.Pattern = `[a-z]+` },
		"minimum": func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.HeaderRules[1].Validation.MinLength = new(4)
		},
		"maximum": func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.HeaderRules[1].Validation.MaxLength = new(11)
		},
		"enum": func(c *runtimeconfig.HarpoonTargetTemplate) { c.HeaderRules[2].Validation.Enum = []string{"full"} },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			changed := richHeaderTestConfig()
			mutate(changed)
			policy, err := CompileTargetTemplate(changed)
			require.NoError(t, err)
			require.NotEqual(t, original.PolicyDigest(), policy.PolicyDigest())
		})
	}
	cfg.HeaderRules[1].ForwardAs = "X-Mutated"
	*cfg.HeaderRules[1].Validation.MaxLength = 1
	cfg.HeaderRules[2].Validation.Enum[0] = "bad"
	headers, err := original.ValidateCallerHeaders(richHeaderTestValues())
	require.NoError(t, err)
	require.Equal(t, "req-123", headers.Get("X-Private-Correlation"))
	public, _ := original.templateHeadersSchema()
	properties := public["properties"].(map[string]any)
	properties["X-Mode"].(map[string]any)["enum"].([]string)[0] = "bad"
	fresh, _ := original.templateHeadersSchema()
	encoded, err := json.Marshal(fresh)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "bad")
	first := richHeaderTestConfig()
	second := richHeaderTestConfig()
	second.HeaderRules[2].Validation.Enum = []string{"full", "summary"}
	second.HeaderRules[1].Name = "x-trace"
	second.HeaderRules[1].ForwardAs = "x-private-correlation"
	second.HeaderRules[0], second.HeaderRules[2] = second.HeaderRules[2], second.HeaderRules[0]
	one, err := CompileTargetTemplate(first)
	require.NoError(t, err)
	two, err := CompileTargetTemplate(second)
	require.NoError(t, err)
	require.Equal(t, one.PolicyDigest(), two.PolicyDigest())
	legacy := templateTestConfig()
	legacy.AllowedHeaders = []string{"X-Tag"}
	canonical := templateTestConfig()
	canonical.HeaderRules = []runtimeconfig.HarpoonHeaderRule{{Name: "x-tag", Legacy: true}}
	one, err = CompileTargetTemplate(legacy)
	require.NoError(t, err)
	two, err = CompileTargetTemplate(canonical)
	require.NoError(t, err)
	require.Equal(t, one.PolicyDigest(), two.PolicyDigest())
}

func TestHeaderRulesDiscoverySharedProjectionAndSuccessfulCall(t *testing.T) {
	t.Parallel()
	logger := runtimeRegistryTestLogger()
	cfg := richHeaderTestConfig()
	cfg.Parameters["resourceId"] = runtimeconfig.HarpoonTemplateParameter{Type: "string", Required: true, Enum: []string{"one"}, MaxLength: 3}
	registry, err := NewRegistry(logger, false, []Target{{Label: "resource", Template: cfg}})
	require.NoError(t, err)
	calls := 0
	server, err := NewServer(&runtimeconfig.HarpoonConfig{}, registry, logger, WithHTTPTransport(templateServerTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		require.Equal(t, "Bearer caller-secret", req.Header.Get("Authorization"))
		require.Equal(t, "req-123", req.Header.Get("X-Private-Correlation"))
		require.Empty(t, req.Header.Values("X-Trace"))
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header), Request: req}, nil
	})))
	require.NoError(t, err)
	invocation := server.listTargets(listTargetsRequest{}).Targets[0].Invocation
	require.Empty(t, invocation.Examples, "never create an example with a required credential")
	public, err := json.Marshal(invocation)
	require.NoError(t, err)
	for _, private := range []string{"forward_as", "X-Private-Correlation", "inventory.example", "credential", "caller-secret"} {
		require.NotContains(t, string(public), private)
	}
	label := invocation.InputSchema["properties"].(map[string]any)["label"].(map[string]any)["const"].(string)
	require.True(t, isPolicyBoundTemplateLabel(label))
	for _, schemaInput := range []any{invocation.InputSchema, server.callTargetInputSchema()} {
		encoded, err := json.Marshal(schemaInput)
		require.NoError(t, err)
		var schema validateschema.Schema
		require.NoError(t, json.Unmarshal(encoded, &schema))
		resolved, err := schema.Resolve(nil)
		require.NoError(t, err)
		values := map[string]any{"label": label, "parameters": map[string]any{"resourceId": "one"}, "headers": map[string]any{"Authorization": "Bearer caller-secret", "X-Trace": "req-123", "X-Mode": "full"}}
		require.NoError(t, resolved.Validate(values))
		delete(values["headers"].(map[string]any), "Authorization")
		require.Error(t, resolved.Validate(values))
		values["headers"].(map[string]any)["Authorization"] = "Basic caller-secret"
		require.Error(t, resolved.Validate(values))
		values["headers"].(map[string]any)["Authorization"] = "Bearer caller-secret"
		values["headers"].(map[string]any)["X-Private-Correlation"] = "req-123"
		require.Error(t, resolved.Validate(values))
		delete(values, "headers")
		require.Error(t, resolved.Validate(values))
	}
	top, err := json.Marshal(server.callTargetInputSchema())
	require.NoError(t, err)
	var schemaMap map[string]any
	require.NoError(t, json.Unmarshal(top, &schemaMap))
	branches := schemaMap["oneOf"].([]any)
	require.Len(t, branches, 2)
	branchHeaders := branches[1].(map[string]any)["properties"].(map[string]any)["headers"]
	publicHeaders, err := json.Marshal(invocation.InputSchema["properties"].(map[string]any)["headers"])
	require.NoError(t, err)
	var wantHeaders any
	require.NoError(t, json.Unmarshal(publicHeaders, &wantHeaders))
	require.Equal(t, wantHeaders, branchHeaders)
	args, err := json.Marshal(map[string]any{"label": label, "parameters": map[string]any{"resourceId": "one"}, "headers": richHeaderTestValues()})
	require.NoError(t, err)
	result, err := server.callTemplateHandler(context.Background(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: callTargetTool, Arguments: args}})
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Equal(t, 1, calls)
}

func TestHeaderRulesBudgetsAndBodyManagedCollisions(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"Proxy-Authenticate", "Proxy-Custom", "Mcp-Session-Id", "X-Tunnel-Custom", "X-Openai-Internal-Custom", "Content-Type", "Content-Encoding"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, rename := range []bool{false, true} {
				cfg := templateTestConfig()
				cfg.Method = http.MethodPost
				required := false
				cfg.BodyPolicy = &runtimeconfig.HarpoonTemplateBodyPolicy{Required: &required, MaxBytes: 100, ContentTypes: []string{"application/json"}, Validation: &runtimeconfig.HarpoonTemplateBodyValidation{JSON: true}}
				rule := runtimeconfig.HarpoonHeaderRule{Name: name, Description: "Public header"}
				if rename {
					rule.Name = "X-Public"
					rule.ForwardAs = name
				}
				cfg.HeaderRules = []runtimeconfig.HarpoonHeaderRule{rule}
				_, err := CompileTargetTemplate(cfg)
				require.Error(t, err)
			}
		})
	}
	cfg := templateTestConfig()
	for i := range maxTemplateHeaders {
		cfg.HeaderRules = append(cfg.HeaderRules, runtimeconfig.HarpoonHeaderRule{Name: "X-Header-" + strings.Repeat("a", i+1), Description: "Optional value"})
	}
	policy, err := CompileTargetTemplate(cfg)
	require.NoError(t, err)
	_, err = policy.ValidateCallerHeaders(nil)
	require.NoError(t, err)
	cfg.Headers = map[string]string{"Accept": "application/json"}
	_, err = CompileTargetTemplate(cfg)
	require.ErrorContains(t, err, "too many headers")
	for _, rename := range []bool{false, true} {
		cfg := templateTestConfig()
		source, destination := "X-Tag", strings.Repeat("A", 128)
		if rename {
			source, destination = destination, source
		}
		cfg.HeaderRules = []runtimeconfig.HarpoonHeaderRule{{Name: source, ForwardAs: destination, Description: "A bounded value"}}
		policy, err := CompileTargetTemplate(cfg)
		require.NoError(t, err)
		// One spelling fits and the other exceeds the aggregate bound.
		value := strings.Repeat("v", maxTemplateHeaderBytes-len("User-Agent")-len(version.UserAgent)-len("X-Tag"))
		_, err = policy.ValidateCallerHeaders(map[string]string{source: value})
		require.ErrorContains(t, err, "size limit")
	}
}

func TestHeaderRulesMCPValidationNeverReflectsSecrets(t *testing.T) {
	t.Parallel()
	logger := runtimeRegistryTestLogger()
	registry, err := NewRegistry(logger, false, []Target{{Label: "resource", Template: richHeaderTestConfig()}})
	require.NoError(t, err)
	calls := 0
	server, err := NewServer(&runtimeconfig.HarpoonConfig{}, registry, logger, WithHTTPTransport(templateServerTransport(func(*http.Request) (*http.Response, error) { calls++; return nil, nil })))
	require.NoError(t, err)
	invocation := server.listTargets(listTargetsRequest{}).Targets[0].Invocation
	label := invocation.InputSchema["properties"].(map[string]any)["label"].(map[string]any)["const"].(string)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.MCPServer().Connect(ctx, &legacyProtocolForTestingTransport{base: serverTransport}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, serverSession.Close()) })
	client := mcp.NewClient(&mcp.Implementation{Name: "header-privacy-test", Version: "test"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, clientSession.Close()) })
	const secret = "sensitive-caller-value-never-reflect"
	for _, values := range []map[string]string{
		{"Authorization": "Basic " + secret, "X-Trace": "req-123"},
		{"Authorization": "Bearer valid", "X-Trace": "req-123", "X-Mode": secret},
		{"Authorization": "Bearer valid", "X-Trace": "req-123", secret: secret},
		{"Authorization": "Bearer valid", "X-Trace": "req-123", "x-trace": secret},
	} {
		result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{Name: callTargetTool, Arguments: map[string]any{"label": label, "parameters": map[string]any{"resourceId": "one"}, "headers": values}})
		require.NoError(t, err)
		require.True(t, result.IsError)
		encoded, err := json.Marshal(result)
		require.NoError(t, err)
		require.NotContains(t, string(encoded), secret)
	}
	require.Zero(t, calls)
}

func TestHeaderRulesMCPLegacyCaseInsensitiveCompatibility(t *testing.T) {
	t.Parallel()
	cfg := templateTestConfig()
	cfg.AllowedHeaders = []string{"X-Request-Tag"}
	logger := runtimeRegistryTestLogger()
	registry, err := NewRegistry(logger, false, []Target{{Label: "legacy", Template: cfg}, {Label: "rich", Template: richHeaderTestConfig()}})
	require.NoError(t, err)
	var received []string
	server, err := NewServer(&runtimeconfig.HarpoonConfig{}, registry, logger, WithHTTPTransport(templateServerTransport(func(req *http.Request) (*http.Response, error) {
		received = append(received, req.Header.Get("X-Request-Tag"))
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header), Request: req}, nil
	})))
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.MCPServer().Connect(ctx, &legacyProtocolForTestingTransport{base: serverTransport}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, serverSession.Close()) })
	client := mcp.NewClient(&mcp.Implementation{Name: "legacy-header-case-test", Version: "test"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, clientSession.Close()) })
	for _, value := range []string{"", "café", "request-123"} {
		result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{Name: callTargetTool, Arguments: map[string]any{"label": "legacy", "parameters": map[string]any{"resourceId": "one"}, "headers": map[string]string{"x-request-tag": value}}})
		require.NoError(t, err)
		require.False(t, result.IsError)
	}
	require.Equal(t, []string{"", "café", "request-123"}, received)
}

func TestCredentialHeaderEnumsRejectConfigurationBeforeDiscovery(t *testing.T) {
	t.Parallel()
	const secret = "Bearer synthetic-pinned-credential"
	for _, header := range []struct{ name, forwardAs string }{
		{name: "Authorization"}, {name: "X-API-Key"}, {name: "API-Key"},
		{name: "X-Provided", forwardAs: "Authorization"},
	} {
		for _, key := range []string{"header_rules", "allowed_headers"} {
			for _, validation := range []struct {
				name, pattern string
				enum          []string
			}{
				{name: "enum only", enum: []string{secret}},
				{name: "pattern and enum", pattern: `Bearer [A-Za-z-]+`, enum: []string{secret}},
				{name: "empty enum with pattern", pattern: `Bearer [A-Za-z-]+`, enum: []string{}},
			} {
				t.Run(header.name+"/"+key+"/"+validation.name, func(t *testing.T) {
					t.Parallel()
					base, err := json.Marshal(templateTestConfig())
					require.NoError(t, err)
					var input map[string]any
					require.NoError(t, json.Unmarshal(base, &input))
					input[key] = []any{map[string]any{
						"name": header.name, "forward_as": header.forwardAs,
						"description": "Caller credential", "credential": true,
						"validation": map[string]any{"pattern": validation.pattern, "enum": validation.enum, "min_length": 8, "max_length": 128},
					}}
					encoded, err := json.Marshal(input)
					require.NoError(t, err)
					var cfg runtimeconfig.HarpoonTargetTemplate
					require.NoError(t, json.Unmarshal(encoded, &cfg), "syntax parsing leaves semantic enforcement to the compiler")
					policy, err := CompileTargetTemplate(&cfg)
					require.Nil(t, policy)
					require.ErrorContains(t, err, "credential rules cannot configure enum values")
					require.NotContains(t, err.Error(), secret)
					registry, err := NewRegistry(runtimeRegistryTestLogger(), false, []Target{{Label: "credential_target", Template: &cfg}})
					require.Nil(t, registry, "invalid credential policy must never reach discovery")
					require.ErrorContains(t, err, "credential rules cannot configure enum values")
					require.NotContains(t, err.Error(), secret)
					profile, err := json.Marshal(map[string]any{"config_version": 2, "harpoon": map[string]any{"targets": []any{map[string]any{"label": "credential_target", "template": input}}}})
					require.NoError(t, err)
					for _, validate := range []func(string, []byte, runtimeconfig.TemplatePolicyValidator) error{
						runtimeconfig.ValidateProfileBytesWithTemplateValidator,
						runtimeconfig.ValidateFullProfileBytesWithTemplateValidator,
					} {
						err := validate("header-rules.yaml", profile, func(policy *runtimeconfig.HarpoonTargetTemplate) error {
							_, err := CompileTargetTemplate(policy)
							return err
						})
						require.ErrorContains(t, err, "credential rules cannot configure enum values")
						require.NotContains(t, err.Error(), secret)
					}
				})
			}
		}
	}
}

func TestHeaderDiscoveryNeverProjectsCredentialEnums(t *testing.T) {
	t.Parallel()
	policy, err := CompileTargetTemplate(richHeaderTestConfig())
	require.NoError(t, err)
	// Deliberately corrupt only the internal enum after compilation to exercise
	// the public projection independently of the compiler's rejection guard.
	const secret = "Bearer synthetic-projection-secret"
	rule := policy.headerRules["Authorization"]
	rule.schema.Validation.Enum = []string{secret}
	policy.headerRules["Authorization"] = rule
	registry, err := NewRegistry(runtimeRegistryTestLogger(), false, []Target{{Label: "credential_target", template: policy, BaseURL: &policy.origin}})
	require.NoError(t, err)
	server, err := NewServer(&runtimeconfig.HarpoonConfig{}, registry, runtimeRegistryTestLogger())
	require.NoError(t, err)
	for _, discovery := range []any{server.callTargetInputSchema(), server.listTargets(listTargetsRequest{})} {
		encoded, err := json.Marshal(discovery)
		require.NoError(t, err)
		require.NotContains(t, string(encoded), secret)
	}
	headers, _ := policy.templateHeadersSchema()
	properties := headers["properties"].(map[string]any)
	require.NotContains(t, properties["Authorization"].(map[string]any), "enum")
	require.Equal(t, []string{"summary", "full"}, properties["X-Mode"].(map[string]any)["enum"], "noncredential enums remain public validation metadata")
}
