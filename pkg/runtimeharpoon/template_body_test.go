package runtimeharpoon

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	validateschema "github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
	"github.com/openai/tunnel-client/pkg/version"
)

func writeTemplateTestConfig(method string) *runtimeconfig.HarpoonTargetTemplate {
	cfg := templateTestConfig()
	cfg.Method = method
	required := true
	cfg.BodyPolicy = &runtimeconfig.HarpoonTemplateBodyPolicy{
		ContentTypes: []string{"application/json"}, MaxBytes: 256, Required: &required,
		Validation: &runtimeconfig.HarpoonTemplateBodyValidation{JSON: true, Enum: []string{`{"state":"ready"}`, `{"state":"done"}`}},
	}
	return cfg
}

func TestTemplateWritePolicyRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(*runtimeconfig.HarpoonTargetTemplate){
		"delete":            func(c *runtimeconfig.HarpoonTargetTemplate) { c.Method = http.MethodDelete },
		"patch":             func(c *runtimeconfig.HarpoonTargetTemplate) { c.Method = http.MethodPatch },
		"method casing":     func(c *runtimeconfig.HarpoonTargetTemplate) { c.Method = "post" },
		"get body policy":   func(c *runtimeconfig.HarpoonTargetTemplate) { c.Method = http.MethodGet },
		"missing policy":    func(c *runtimeconfig.HarpoonTargetTemplate) { c.BodyPolicy = nil },
		"missing required":  func(c *runtimeconfig.HarpoonTargetTemplate) { c.BodyPolicy.Required = nil },
		"missing validator": func(c *runtimeconfig.HarpoonTargetTemplate) { c.BodyPolicy.Validation = nil },
		"empty validator": func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.BodyPolicy.Validation = &runtimeconfig.HarpoonTemplateBodyValidation{}
		},
		"zero bytes":      func(c *runtimeconfig.HarpoonTargetTemplate) { c.BodyPolicy.MaxBytes = 0 },
		"excessive bytes": func(c *runtimeconfig.HarpoonTargetTemplate) { c.BodyPolicy.MaxBytes = maxTemplateBodyBytes + 1 },
		"empty types":     func(c *runtimeconfig.HarpoonTargetTemplate) { c.BodyPolicy.ContentTypes = nil },
		"wildcard type":   func(c *runtimeconfig.HarpoonTargetTemplate) { c.BodyPolicy.ContentTypes = []string{"application/*"} },
		"type parameters": func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.BodyPolicy.ContentTypes = []string{"application/json; charset=utf-8"}
		},
		"type casing":    func(c *runtimeconfig.HarpoonTargetTemplate) { c.BodyPolicy.ContentTypes = []string{"Application/JSON"} },
		"type malformed": func(c *runtimeconfig.HarpoonTargetTemplate) { c.BodyPolicy.ContentTypes = []string{"json"} },
		"type repeated": func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.BodyPolicy.ContentTypes = []string{"application/json", "application/json"}
		},
		"json without validator": func(c *runtimeconfig.HarpoonTargetTemplate) { c.BodyPolicy.Validation.JSON = false },
		"structured json without validator": func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.BodyPolicy.ContentTypes = []string{"application/problem+json"}
			c.BodyPolicy.Validation.JSON = false
		},
		"pattern malformed":         func(c *runtimeconfig.HarpoonTargetTemplate) { c.BodyPolicy.Validation.Pattern = "[" },
		"pattern not portable":      func(c *runtimeconfig.HarpoonTargetTemplate) { c.BodyPolicy.Validation.Pattern = "(?i).*" },
		"invalid enum json":         func(c *runtimeconfig.HarpoonTargetTemplate) { c.BodyPolicy.Validation.Enum = []string{"invalid"} },
		"enum over byte limit":      func(c *runtimeconfig.HarpoonTargetTemplate) { c.BodyPolicy.MaxBytes = 1 },
		"enum pattern disagreement": func(c *runtimeconfig.HarpoonTargetTemplate) { c.BodyPolicy.Validation.Pattern = "x" },
		"enum repeated":             func(c *runtimeconfig.HarpoonTargetTemplate) { c.BodyPolicy.Validation.Enum = []string{"{}", "{}"} },
		"fixed content type": func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.Headers = map[string]string{"content-type": "application/json"}
		},
		"caller content type": func(c *runtimeconfig.HarpoonTargetTemplate) { c.AllowedHeaders = []string{"Content-Type"} },
		"fixed encoding": func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.Headers = map[string]string{"Content-Encoding": "gzip"}
		},
		"caller encoding": func(c *runtimeconfig.HarpoonTargetTemplate) { c.AllowedHeaders = []string{"Content-Encoding"} },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := writeTemplateTestConfig(http.MethodPost)
			change(cfg)
			_, err := CompileTargetTemplate(cfg)
			require.Error(t, err)
		})
	}
}

func TestTemplateBodyValidationAndPresence(t *testing.T) {
	t.Parallel()
	text := func(s string) *string { return &s }
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			cfg := writeTemplateTestConfig(method)
			cfg.BodyPolicy.Validation.Enum = nil
			cfg.BodyPolicy.MaxBytes = 8
			policy, err := CompileTargetTemplate(cfg)
			require.NoError(t, err)
			for _, test := range []struct {
				body, contentType *string
				valid             bool
			}{
				{text(`{"x":1}`), text("application/json"), true},
				{text(`"ééé"`), text("application/json"), true},
				{text(`"éééé"`), text("application/json"), false},
				{text(`{}`), text("application/json; charset=utf-8"), false},
				{text(`{}`), text("text/plain"), false},
				{text(`{}`), nil, false}, {nil, text("application/json"), false}, {nil, nil, false},
				{text(""), text("application/json"), false},
				{text("invalid"), text("application/json"), false},
				{text("\"\xff\""), text("application/json"), false},
				{text(`"\ud800"`), text("application/json"), false},
			} {
				err := policy.bodyPolicy.validate(test.body, test.contentType)
				require.Equal(t, test.valid, err == nil, "body=%v content_type=%v error=%v", test.body, test.contentType, err)
			}
			*cfg.BodyPolicy.Required = false
			cfg.BodyPolicy.ContentTypes = []string{"text/plain"}
			cfg.BodyPolicy.Validation = &runtimeconfig.HarpoonTemplateBodyValidation{Pattern: `[ -~]*`}
			policy, err = CompileTargetTemplate(cfg)
			require.NoError(t, err)
			require.NoError(t, policy.bodyPolicy.validate(nil, nil))
			require.NoError(t, policy.bodyPolicy.validate(text(""), text("text/plain")))
		})
	}
	get, err := CompileTargetTemplate(templateTestConfig())
	require.NoError(t, err)
	require.NoError(t, get.bodyPolicy.validate(nil, nil))
	require.Error(t, get.bodyPolicy.validate(text(""), nil))
	require.Error(t, get.bodyPolicy.validate(nil, text("")))
}

func TestTemplateBodyPatternsRejectNonportableSyntax(t *testing.T) {
	t.Parallel()
	for _, pattern := range []string{
		`\d+`, `\D+`, `\s+`, `\S+`, `\w+`, `\W+`, `[\s\S]*`,
		`.*`, `[^a]+`, `[a[^b]]`, `[a[:digit:]]`, `é`,
		`x{word}`, `x{,2}`, `x{2`, `x{02}`, `x{1,03}`, `x}`, `]`, `\-`,
		`^*`, `$+`, `a$?`, `^{1,2}`, `^??`, `$*?`,
	} {
		t.Run(pattern, func(t *testing.T) {
			t.Parallel()
			cfg := writeTemplateTestConfig(http.MethodPost)
			cfg.BodyPolicy.ContentTypes = []string{"text/plain"}
			cfg.BodyPolicy.Validation = &runtimeconfig.HarpoonTemplateBodyValidation{Pattern: pattern}
			_, err := CompileTargetTemplate(cfg)
			require.Error(t, err)
		})
	}
	// Preserve the existing ASCII identifier contract separately from bodies.
	for _, pattern := range []string{`\d+`, `\s+`, `\S+`, `.*`, `[^a]+`} {
		require.NoError(t, validateTemplatePattern(pattern))
	}
	for _, test := range []struct{ pattern, body string }{
		{`[ -~]*`, `{"state":"ready"}`},
		{`state:(ready|done)`, "state:ready"},
		{`(?:a|b){1,3}`, "aba"},
		{`a{1,}`, "aaa"},
		{`a{2}`, "aa"},
		{`\[\{[A-Z]+\}\]\.`, "[{READY}]."},
		{`[.\]^-]+`, ".]^-"},
		{`\\s`, `\s`},
		{`(?:^)*a(?:$)+`, "a"},
		{`\^+\$?`, "^^$"},
	} {
		t.Run(test.pattern, func(t *testing.T) {
			t.Parallel()
			cfg := writeTemplateTestConfig(http.MethodPost)
			cfg.BodyPolicy.ContentTypes = []string{"text/plain"}
			cfg.BodyPolicy.Validation = &runtimeconfig.HarpoonTemplateBodyValidation{Pattern: test.pattern}
			compiled, err := CompileTargetTemplate(cfg)
			require.NoError(t, err)
			contentType := "text/plain"
			require.NoError(t, compiled.bodyPolicy.validate(&test.body, &contentType))
		})
	}
}

func TestTemplateBodyPatternSchemaAndRuntimeRejectUnicodeAndControls(t *testing.T) {
	t.Parallel()
	cfg := writeTemplateTestConfig(http.MethodPost)
	*cfg.BodyPolicy.Required = false
	cfg.BodyPolicy.ContentTypes = []string{"text/plain"}
	cfg.BodyPolicy.Validation = &runtimeconfig.HarpoonTemplateBodyValidation{Pattern: `[ -~]*`}
	logger := runtimeRegistryTestLogger()
	registry, err := NewRegistry(logger, false, []Target{{Label: "write", Template: cfg}})
	require.NoError(t, err)
	server, err := NewServer(&runtimeconfig.HarpoonConfig{MaxResponseBytes: 1024}, registry, logger)
	require.NoError(t, err)
	target := server.listTargets(listTargetsRequest{}).Targets[0]
	properties := target.Invocation.InputSchema["properties"].(map[string]any)
	bodySchema := properties["body"].(map[string]any)
	require.Equal(t, map[string]any{"pattern": "[^ -~]"}, bodySchema["not"])
	encoded, err := json.Marshal(bodySchema)
	require.NoError(t, err)
	var schema validateschema.Schema
	require.NoError(t, json.Unmarshal(encoded, &schema))
	resolved, err := schema.Resolve(nil)
	require.NoError(t, err)
	compiled, err := CompileTargetTemplate(cfg)
	require.NoError(t, err)
	contentType := "text/plain"
	for _, body := range []string{"", "state:ready", " []{}\\^$.-~"} {
		require.NoError(t, resolved.Validate(body), "%q", body)
		require.NoError(t, compiled.bodyPolicy.validate(&body, &contentType), "%q", body)
	}
	for _, body := range []string{"é", "\u00a0", "ready\n", "ready\r", "ready\v", "\u2028", "\u2029", "😀"} {
		require.Error(t, resolved.Validate(body), "%q", body)
		require.Error(t, compiled.bodyPolicy.validate(&body, &contentType), "%q", body)
	}
}

func TestTemplateBodyPolicyDigestAndCopies(t *testing.T) {
	t.Parallel()
	cfg := writeTemplateTestConfig(http.MethodPost)
	policy, err := CompileTargetTemplate(cfg)
	require.NoError(t, err)
	original := policy.PolicyDigest()
	for name, change := range map[string]func(*runtimeconfig.HarpoonTargetTemplate){
		"method": func(c *runtimeconfig.HarpoonTargetTemplate) { c.Method = http.MethodPut },
		"content type": func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.BodyPolicy.ContentTypes = []string{"application/problem+json"}
		},
		"byte limit": func(c *runtimeconfig.HarpoonTargetTemplate) { c.BodyPolicy.MaxBytes-- },
		"required":   func(c *runtimeconfig.HarpoonTargetTemplate) { *c.BodyPolicy.Required = false },
		"json": func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.BodyPolicy.ContentTypes = []string{"text/plain"}
			c.BodyPolicy.Validation.JSON = false
		},
		"pattern": func(c *runtimeconfig.HarpoonTargetTemplate) { c.BodyPolicy.Validation.Pattern = `[ -~]*` },
		"enum": func(c *runtimeconfig.HarpoonTargetTemplate) {
			c.BodyPolicy.Validation.Enum = c.BodyPolicy.Validation.Enum[:1]
		},
	} {
		t.Run(name, func(t *testing.T) {
			other := writeTemplateTestConfig(http.MethodPost)
			change(other)
			compiled, err := CompileTargetTemplate(other)
			require.NoError(t, err)
			require.NotEqual(t, original, compiled.PolicyDigest())
		})
	}
	cfg.BodyPolicy.ContentTypes[0] = "text/plain"
	cfg.BodyPolicy.Validation.Enum[0] = "changed"
	public := policy.bodyPolicy.publicPolicy()
	public.Validation.Enum[0] = "also changed"
	public.ContentTypes[0] = "text/plain"
	body, contentType := `{"state":"ready"}`, "application/json"
	require.NoError(t, policy.bodyPolicy.validate(&body, &contentType))
	require.Equal(t, original, policy.PolicyDigest())
	other := writeTemplateTestConfig(http.MethodPost)
	other.BodyPolicy.Validation.Enum = []string{`{"state":"done"}`, `{"state":"ready"}`}
	compiled, err := CompileTargetTemplate(other)
	require.NoError(t, err)
	require.Equal(t, original, compiled.PolicyDigest())
}

func TestTemplateWriteBoundaryBindsBodyAndDisablesReplay(t *testing.T) {
	t.Parallel()
	cfg := writeTemplateTestConfig(http.MethodPut)
	cfg.Headers = map[string]string{"Authorization": "Bearer pinned"}
	policy, err := CompileTargetTemplate(cfg)
	require.NoError(t, err)
	params := map[string]any{"resourceId": "one"}
	u, err := policy.Render(params)
	require.NoError(t, err)
	body, contentType := `{"state":"ready"}`, "application/json"
	request := func() *http.Request {
		req, err := http.NewRequest(http.MethodPut, u.String(), io.NopCloser(strings.NewReader(body)))
		require.NoError(t, err)
		req.ContentLength = int64(len(body))
		req.Header = policy.FixedHeaders()
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("User-Agent", version.UserAgent)
		return req
	}
	req := request()
	require.NoError(t, policy.validateRequest(req, params, &body, &contentType))
	require.Nil(t, req.GetBody)
	actual, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Equal(t, body, string(actual))
	for name, mutate := range map[string]func(*http.Request){
		"method":                    func(r *http.Request) { r.Method = http.MethodPost },
		"same size changed payload": func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{"state":"other"}`)) },
		"short body":                func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{}`)) },
		"long body":                 func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(body + "x")) },
		"missing body":              func(r *http.Request) { r.Body = nil },
		"replay body": func(r *http.Request) {
			r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(body)), nil }
		},
		"content type":         func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") },
		"missing content type": func(r *http.Request) { r.Header.Del("Content-Type") },
		"credential":           func(r *http.Request) { r.Header.Set("Authorization", "Bearer other") },
		"content length":       func(r *http.Request) { r.ContentLength++ },
		"trailer":              func(r *http.Request) { r.Trailer = http.Header{"X-Extra": []string{"value"}} },
	} {
		t.Run(name, func(t *testing.T) {
			r := request()
			mutate(r)
			require.Error(t, policy.validateRequest(r, params, &body, &contentType))
		})
	}
}

func TestTemplateWriteDiscoverySchema(t *testing.T) {
	t.Parallel()
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			cfg := writeTemplateTestConfig(method)
			p := cfg.Parameters["resourceId"]
			p.Examples = []string{"one"}
			cfg.Parameters["resourceId"] = p
			logger := runtimeRegistryTestLogger()
			registry, err := NewRegistry(logger, false, []Target{{Label: "write", Template: cfg}, {Label: "read", Template: templateTestConfig()}})
			require.NoError(t, err)
			server, err := NewServer(&runtimeconfig.HarpoonConfig{MaxResponseBytes: 1024}, registry, logger)
			require.NoError(t, err)
			for _, target := range server.listTargets(listTargetsRequest{}).Targets {
				if target.Label != "write" {
					continue
				}
				require.Equal(t, []string{method}, target.AllowedMethods)
				require.Len(t, target.Invocation.Examples, 1)
				encoded, err := json.Marshal(target.Invocation.InputSchema)
				require.NoError(t, err)
				var schema validateschema.Schema
				require.NoError(t, json.Unmarshal(encoded, &schema))
				resolved, err := schema.Resolve(nil)
				require.NoError(t, err)
				require.NoError(t, resolved.Validate(target.Invocation.Examples[0]))
				for _, key := range []string{"operation", "body", "content_type"} {
					example := map[string]any{}
					for k, v := range target.Invocation.Examples[0] {
						example[k] = v
					}
					delete(example, key)
					require.Error(t, resolved.Validate(example))
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			st, ct := mcp.NewInMemoryTransports()
			ss, err := server.MCPServer().Connect(ctx, st, nil)
			require.NoError(t, err)
			defer func() { _ = ss.Close() }()
			cs, err := mcp.NewClient(&mcp.Implementation{Name: "write-schema-test", Version: "1"}, nil).Connect(ctx, ct, nil)
			require.NoError(t, err)
			defer func() { _ = cs.Close() }()
			tools, err := cs.ListTools(ctx, nil)
			require.NoError(t, err)
			for _, tool := range tools.Tools {
				if tool.Name == callTargetTool {
					require.NotNil(t, tool.Annotations)
					require.False(t, tool.Annotations.ReadOnlyHint)
					require.False(t, tool.Annotations.IdempotentHint)
				}
			}
		})
	}
}

func TestTemplateBodyStrictJSONDecoding(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		`{"label":"write","parameters":{"resourceId":"one"},"body":"\ud800","content_type":"text/plain"}`,
		`{"label":"write","parameters":{"resourceId":"one"},"body":"\udc00","content_type":"text/plain"}`,
		`{"label":"write","parameters":{"resourceId":"one"},"body":"\ud800x","content_type":"text/plain"}`,
		"{\"label\":\"write\",\"parameters\":{\"resourceId\":\"one\"},\"body\":\"\xff\",\"content_type\":\"text/plain\"}",
	} {
		var p callTargetTemplateRequest
		require.Error(t, decodeTemplateArguments([]byte(raw), &p))
	}
	for _, raw := range []string{`"\ud83d\ude00"`, `"literal \\ud800"`, `"é"`} {
		require.True(t, validTemplateJSONStrings([]byte(raw)), raw)
	}
}

func TestTemplateWriteOperationRejectsLegacyAndMismatchedCalls(t *testing.T) {
	t.Parallel()
	write := writeTemplateTestConfig(http.MethodPost)
	*write.BodyPolicy.Required = false
	logger := runtimeRegistryTestLogger()
	registry, err := NewRegistry(logger, false, []Target{{Label: "write", Template: write}, {Label: "get", Template: templateTestConfig()}})
	require.NoError(t, err)
	server, err := NewServer(&runtimeconfig.HarpoonConfig{MaxResponseBytes: 1024}, registry, logger)
	require.NoError(t, err)
	server.httpTransport = templateServerTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid operation must never reach the outbound transport")
		return nil, nil
	})
	other, err := CompileTargetTemplate(writeTemplateTestConfig(http.MethodPut))
	require.NoError(t, err)
	for _, params := range []callTargetTemplateRequest{
		{Label: "write", Parameters: map[string]any{"resourceId": "one"}},
		{Label: "write", Parameters: map[string]any{"resourceId": "one"}, Operation: &other.operationToken},
		{Label: "get", Parameters: map[string]any{"resourceId": "one"}, Operation: &other.operationToken},
	} {
		_, err := server.callTargetTemplate(context.Background(), params)
		require.Error(t, err)
	}
	compiled, err := CompileTargetTemplate(write)
	require.NoError(t, err)
	write.Origin = "https://different-private.example"
	write.Headers = map[string]string{"Authorization": "Bearer different-private-secret"}
	changedPrivate, err := CompileTargetTemplate(write)
	require.NoError(t, err)
	require.Equal(t, compiled.operationToken, changedPrivate.operationToken, "operation token must not fingerprint private routing or credentials")
	require.NotEqual(t, compiled.PolicyDigest(), changedPrivate.PolicyDigest())
}

func TestUnifiedTargetDispatchPreservesRawTemplateValidation(t *testing.T) {
	t.Parallel()
	logger := runtimeRegistryTestLogger()
	registry, err := NewRegistry(logger, false, []Target{
		{Label: "write", Template: writeTemplateTestConfig(http.MethodPost)},
		{Label: "get", Template: templateTestConfig()},
		{Label: "exact", BaseURL: runtimeRegistryTestURL(t, "https://exact.example/resource")},
	})
	require.NoError(t, err)
	server, err := NewServer(&runtimeconfig.HarpoonConfig{MaxResponseBytes: 1024}, registry, logger)
	require.NoError(t, err)
	requests := make(chan string, 4)
	server.httpTransport = templateServerTransport(func(req *http.Request) (*http.Response, error) {
		requests <- req.Method
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: req}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := server.MCPServer().Connect(ctx, st, nil)
	require.NoError(t, err)
	defer func() { _ = ss.Close() }()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "unified-dispatch-test", Version: "1"}, nil).Connect(ctx, ct, nil)
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()
	write, _ := registry.Lookup("write")
	validWrite, err := json.Marshal(map[string]any{
		"label": "write", "parameters": map[string]string{"resourceId": "one"},
		"operation": write.template.operationToken, "body": `{"state":"ready"}`, "content_type": "application/json",
	})
	require.NoError(t, err)
	for _, raw := range []string{
		strings.Replace(string(validWrite), `"resourceId":"one"`, `"resourceId":"two","resourceId":"one"`, 1),
		strings.Replace(string(validWrite), `"body":`, `"body":"ignored","body":`, 1),
		strings.TrimSuffix(string(validWrite), "}") + `,"method":"POST"}`,
		`{"label":"get","parameters":{"resourceId":"one"},"method":"GET"}`,
		`{"label":"exact","parameters":{"resourceId":"one"}}`,
		`{"label":"exact","method":"POST","operation":"invalid"}`,
		`{"label":"exact","method":"POST","content_type":"application/json","body":"{}"}`,
		`{"label":"unknown","parameters":{"resourceId":"one"}}`,
	} {
		result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: callTargetTool, Arguments: json.RawMessage(raw)})
		require.NoError(t, err)
		require.True(t, result.IsError, raw)
	}
	removed, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "call_target_template", Arguments: json.RawMessage(validWrite)})
	require.True(t, err != nil || removed != nil && removed.IsError)
	require.Empty(t, requests, "rejected calls must never fall back to exact routing")
	for _, call := range []struct{ raw, method string }{
		{string(validWrite), http.MethodPost},
		{`{"label":"get","parameters":{"resourceId":"one"}}`, http.MethodGet},
		{`{"label":"exact","method":"PUT","body":"raw exact body"}`, http.MethodPut},
	} {
		result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: callTargetTool, Arguments: json.RawMessage(call.raw)})
		require.NoError(t, err)
		require.False(t, result.IsError, "%+v", result.Content)
		require.Equal(t, call.method, <-requests)
	}
	require.Empty(t, requests)
}
