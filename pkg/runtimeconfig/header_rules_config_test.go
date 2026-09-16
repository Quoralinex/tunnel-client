package runtimeconfig

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const structuredHeaderRulesFixture = `
          - Accept
          - name: X-Request-Token
            description: Token issued by the upstream application
            required: true
            credential: true
            forward_as: Authorization
            validation:
              pattern: '^Bearer [A-Za-z0-9._-]+$'
              min_length: 8
              max_length: 4096
          - name: X-Response-Mode
            description: Optional response mode
            validation:
              enum: ['', compact]
              min_length: 0
              max_length: 64`

func TestLoadHeaderRuleAliasesAcrossFlavors(t *testing.T) {
	t.Parallel()

	for _, key := range []string{"header_rules", "allowed_headers"} {
		for _, flavor := range []Flavor{FlavorRuntime, FlavorRuntimeCloudflared, FlavorFull} {
			t.Run(key+"/"+string(flavor), func(t *testing.T) {
				t.Parallel()
				contents := strings.Replace(templateConfigFixture, "allowed_headers: [Accept]", key+":"+structuredHeaderRulesFixture, 1)
				contents = strings.Replace(contents, "Authorization: env:TEST_TEMPLATE_AUTH", "X-Fixed-Secret: env:TEST_TEMPLATE_AUTH", 1)
				cfg, err := Load([]string{"--config", writeRuntimeConfig(t, contents)}, flavor, lookupEnvMap(map[string]string{
					"TEST_API_KEY": testAPIKey, "TEST_TEMPLATE_AUTH": "Bearer fixed-secret",
				}))
				if err != nil {
					t.Fatal(err)
				}
				rules, err := cfg.Harpoon.Targets[0].Template.NormalizedHeaderRules()
				if err != nil {
					t.Fatal(err)
				}
				minLength, maxLength := 8, 4096
				modeMinLength, modeMaxLength := 0, 64
				want := []HarpoonHeaderRule{
					{Name: "Accept", Legacy: true},
					{Name: "X-Request-Token", Description: "Token issued by the upstream application", Required: true, Credential: true, ForwardAs: "Authorization", Validation: &HarpoonHeaderValidation{
						Pattern: "^Bearer [A-Za-z0-9._-]+$", MinLength: &minLength, MaxLength: &maxLength,
					}},
					{Name: "X-Response-Mode", Description: "Optional response mode", Validation: &HarpoonHeaderValidation{
						Enum: []string{"", "compact"}, MinLength: &modeMinLength, MaxLength: &modeMaxLength,
					}},
				}
				if !reflect.DeepEqual(rules, want) {
					t.Fatalf("loaded header rules = %#v, want %#v", rules, want)
				}
				if !strings.Contains(string(cfg.Runtime.ConfigFileContents), key+":") {
					t.Fatal("config did not retain its original header-rule alias")
				}
			})
		}
	}
}

func TestHeaderRuleConfigRejectsBothAliasesByPresence(t *testing.T) {
	t.Parallel()

	for _, first := range []string{"null", "[]", `["Accept"]`} {
		for _, second := range []string{"null", "[]", `["Accept"]`} {
			t.Run(first+"/"+second, func(t *testing.T) {
				t.Parallel()
				inputs := []struct {
					data      string
					unmarshal func([]byte, any) error
				}{
					{`{"header_rules":` + first + `,"allowed_headers":` + second + `}`, json.Unmarshal},
					{"header_rules: " + first + "\nallowed_headers: " + second + "\n", yaml.Unmarshal},
				}
				for _, input := range inputs {
					var policy HarpoonTargetTemplate
					err := input.unmarshal([]byte(input.data), &policy)
					if err == nil || !strings.Contains(err.Error(), "header_rules and allowed_headers cannot be combined") {
						t.Fatalf("input %s returned %v, want alias conflict", input.data, err)
					}
				}
			})
		}
	}
}

func TestHeaderRuleConfigStrictSchema(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, value, want string }{
		{"null list", "null", "header rules cannot be null"},
		{"unknown rule field", `[{name: Accept, default: anything}]`, "field default not found"},
		{"unknown validation field", `[{name: Accept, validation: {maxLength: 64}}]`, "field maxLength not found"},
		{"duplicate rule field", `[{name: Accept, name: Authorization}]`, "already defined"},
		{"duplicate validation field", `[{name: Accept, validation: {pattern: '^a$', pattern: '^b$'}}]`, "already defined"},
		{"number entry", `[123]`, "must be a string or an object"},
		{"boolean entry", `[false]`, "must be a string or an object"},
		{"null entry", `[null]`, "must be a string or an object"},
		{"array entry", `[[Accept]]`, "must be a string or an object"},
		{"object list", `{name: Accept}`, "cannot unmarshal"},
		{"invalid required", `[{name: Accept, required: no-thanks}]`, "cannot unmarshal"},
		{"invalid credential", `[{name: Accept, credential: no-thanks}]`, "cannot unmarshal"},
		{"invalid min length", `[{name: Accept, validation: {min_length: no-thanks}}]`, "cannot unmarshal"},
		{"invalid enum", `[{name: Accept, validation: {enum: one}}]`, "cannot unmarshal"},
	} {
		for _, key := range []string{"header_rules", "allowed_headers"} {
			t.Run(key+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				contents := strings.Replace(templateConfigFixture, "allowed_headers: [Accept]", key+": "+tc.value, 1)
				for _, validate := range []func(string, []byte) error{ValidateProfileBytes, ValidateFullProfileBytes} {
					err := validate("header-rules.yaml", []byte(contents))
					if err == nil || !strings.Contains(err.Error(), tc.want) {
						t.Fatalf("got %v, want error containing %q", err, tc.want)
					}
				}
			})
		}
	}
}

func TestHeaderRuleJSONStrictSchema(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		`null`,
		`[{"name":"Accept","default":"anything"}]`,
		`[{"name":"Accept","validation":{"maxLength":64}}]`,
		`[{"name":"Accept","name":"Authorization"}]`,
		`[{"name":"Accept","validation":{"pattern":"a","pattern":"b"}}]`,
		`[123]`, `[false]`, `[null]`, `[["Accept"]]`,
		`[{"name":123}]`, `[{"name":"Accept","required":"false"}]`,
		`[{"name":"Accept","validation":{"min_length":1.5}}]`,
	} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			var policy HarpoonTargetTemplate
			if err := json.Unmarshal([]byte(`{"header_rules":`+value+`}`), &policy); err == nil {
				t.Fatal("invalid JSON header rules were accepted")
			}
		})
	}
}

func TestHeaderRuleFieldsDoNotCoerceOrDiscardConstraints(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, fields string }{
		{"numeric name", `"name":123`},
		{"boolean description", `"description":true`},
		{"numeric description", `"description":123`},
		{"numeric destination", `"forward_as":123`},
		{"string required", `"required":"false"`},
		{"string credential", `"credential":"true"`},
		{"null name", `"name":null`},
		{"null description", `"description":null`},
		{"null destination", `"forward_as":null`},
		{"null required", `"required":null`},
		{"null credential", `"credential":null`},
		{"null validation", `"validation":null`},
		{"null pattern", `"validation":{"pattern":null}`},
		{"numeric pattern", `"validation":{"pattern":123}`},
		{"null enum", `"validation":{"enum":null}`},
		{"numeric enum value", `"validation":{"enum":[123]}`},
		{"boolean enum value", `"validation":{"enum":[true]}`},
		{"null enum value", `"validation":{"enum":[null]}`},
		{"null minimum", `"validation":{"min_length":null}`},
		{"null maximum", `"validation":{"max_length":null}`},
		{"fractional minimum", `"validation":{"min_length":1.5}`},
		{"fractional maximum", `"validation":{"max_length":4.5}`},
		{"string minimum", `"validation":{"min_length":"1"}`},
		{"string maximum", `"validation":{"max_length":"64"}`},
	} {
		for _, key := range []string{"header_rules", "allowed_headers"} {
			t.Run(key+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				// JSON flow syntax is also YAML, exercising the identical value
				// through both decoders without coercing it in the fixture.
				data := []byte(`{"` + key + `":[{` + tc.fields + `}]}`)
				for _, unmarshal := range []func([]byte, any) error{yaml.Unmarshal, json.Unmarshal} {
					var policy HarpoonTargetTemplate
					if err := unmarshal(data, &policy); err == nil {
						t.Fatalf("malformed structured field was accepted: %s", data)
					}
				}
			})
		}
	}
}

func TestHeaderRuleOptionalFieldsMayBeOmitted(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"header_rules", "allowed_headers"} {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			data := []byte(`{"` + key + `":["Accept",{"name":"X-Request","description":"Request metadata"},{"name":"X-Other","description":"Other metadata","validation":{}}]}`)
			for _, unmarshal := range []func([]byte, any) error{yaml.Unmarshal, json.Unmarshal} {
				var policy HarpoonTargetTemplate
				if err := unmarshal(data, &policy); err != nil {
					t.Fatal(err)
				}
				rules, err := policy.NormalizedHeaderRules()
				if err != nil {
					t.Fatal(err)
				}
				if len(rules) != 3 || !rules[0].Legacy || rules[1].Legacy || rules[1].Required || rules[1].Credential || rules[1].Validation != nil || rules[2].Validation == nil {
					t.Fatal("omitting optional structured fields changed the policy")
				}
			}
		})
	}
}

func TestHeaderRuleYAMLAnchorsCannotHideMalformedScalarTypes(t *testing.T) {
	t.Parallel()
	for _, scalar := range []string{"123", "1.5", "null", "true"} {
		t.Run(scalar, func(t *testing.T) {
			t.Parallel()
			data := []byte("parameters:\n  id:\n    description: &malformed " + scalar + "\nheader_rules:\n  - name: X-Request\n    description: *malformed\n")
			var policy HarpoonTargetTemplate
			if err := yaml.Unmarshal(data, &policy); err == nil {
				t.Fatal("YAML anchor changed a malformed scalar into a valid header description")
			}
		})
	}
	var policy HarpoonTargetTemplate
	if err := yaml.Unmarshal([]byte("header_rules:\n  - &rule {name: X-First, description: '123', required: false, validation: {enum: ['123'], min_length: 0, max_length: 64}}\n  - <<: *rule\n    name: X-Second\n"), &policy); err != nil {
		t.Fatalf("valid typed values or merged rules were rejected: %v", err)
	}
}

func TestHeaderRulesRoundTripPreservesAliasAndEntryForms(t *testing.T) {
	t.Parallel()

	for _, key := range []string{"header_rules", "allowed_headers"} {
		for _, value := range []string{
			"[Accept]", "[]",
			`[{name: Accept}]`,
			structuredHeaderRulesFixture,
		} {
			t.Run(key+"/"+value, func(t *testing.T) {
				t.Parallel()
				var original HarpoonTargetTemplate
				if err := yaml.Unmarshal([]byte(key+": "+value), &original); err != nil {
					t.Fatal(err)
				}
				for _, format := range []struct {
					name      string
					marshal   func(any) ([]byte, error)
					unmarshal func([]byte, any) error
				}{
					{"YAML", yaml.Marshal, yaml.Unmarshal},
					{"JSON", json.Marshal, json.Unmarshal},
				} {
					encoded, err := format.marshal(original)
					if err != nil {
						t.Fatal(err)
					}
					var fields map[string]any
					if err := format.unmarshal(encoded, &fields); err != nil {
						t.Fatal(err)
					}
					if _, ok := fields[key]; !ok {
						t.Fatalf("%s did not retain alias %q: %s", format.name, key, encoded)
					}
					otherKey := "allowed_headers"
					if key == otherKey {
						otherKey = "header_rules"
					}
					if _, ok := fields[otherKey]; ok {
						t.Fatalf("%s introduced the other alias: %s", format.name, encoded)
					}
					var decoded HarpoonTargetTemplate
					if err := format.unmarshal(encoded, &decoded); err != nil {
						t.Fatal(err)
					}
					before, err := original.NormalizedHeaderRules()
					if err != nil {
						t.Fatal(err)
					}
					after, err := decoded.NormalizedHeaderRules()
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(before, after) {
						t.Fatalf("%s changed header rule semantics: %s", format.name, encoded)
					}
				}
			})
		}
	}
}

func TestHeaderRulesProfileValidationPreservesConstraints(t *testing.T) {
	t.Parallel()

	for _, key := range []string{"header_rules", "allowed_headers"} {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			contents := strings.Replace(templateConfigFixture, "allowed_headers: [Accept]", key+":"+structuredHeaderRulesFixture, 1)
			contents = strings.Replace(contents, "Authorization: env:TEST_TEMPLATE_AUTH", "X-Fixed-Secret: env:TEST_TEMPLATE_AUTH", 1)
			contents = strings.Replace(contents, "enum: ['', compact]", "enum: ['', 'env:DO_NOT_RESOLVE']", 1)
			for _, validate := range []func(string, []byte, TemplatePolicyValidator) error{
				ValidateProfileBytesWithTemplateValidator, ValidateFullProfileBytesWithTemplateValidator,
			} {
				called := false
				err := validate("header-rules.yaml", []byte(contents), func(policy *HarpoonTargetTemplate) error {
					called = true
					if policy.Headers["X-Fixed-Secret"] != "x" {
						t.Fatal("profile validation did not mask the fixed credential reference")
					}
					rules, err := policy.NormalizedHeaderRules()
					if err != nil {
						return err
					}
					if len(rules) != 3 || rules[1].ForwardAs != "Authorization" || rules[1].Validation == nil || rules[2].Validation == nil {
						t.Fatal("profile validation changed header rules")
					}
					credential, mode := rules[1].Validation, rules[2].Validation
					if credential.Pattern != "^Bearer [A-Za-z0-9._-]+$" || len(credential.Enum) != 0 || credential.MinLength == nil || *credential.MinLength != 8 ||
						!reflect.DeepEqual(mode.Enum, []string{"", "env:DO_NOT_RESOLVE"}) || mode.MinLength == nil || *mode.MinLength != 0 {
						t.Fatal("profile validation changed header rule constraints")
					}
					return nil
				})
				if err != nil || !called {
					t.Fatalf("policy validator was not called successfully: %v", err)
				}
			}
		})
	}
}

func TestHeaderRulesClearedListRemainsValidConfig(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"header_rules", "allowed_headers"} {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			var policy HarpoonTargetTemplate
			requireConfigDecode := func(data []byte) {
				t.Helper()
				var decoded HarpoonTargetTemplate
				if err := yaml.Unmarshal(data, &decoded); err != nil {
					t.Fatalf("clearing rules produced invalid config: %s: %v", data, err)
				}
				rules, err := decoded.NormalizedHeaderRules()
				if err != nil || len(rules) != 0 {
					t.Fatalf("cleared rules were retained: %#v, %v", rules, err)
				}
			}
			if err := yaml.Unmarshal([]byte(key+": [{name: Accept}]"), &policy); err != nil {
				t.Fatal(err)
			}
			policy.HeaderRules = nil
			for _, marshal := range []func(any) ([]byte, error){yaml.Marshal, json.Marshal} {
				encoded, err := marshal(policy)
				if err != nil {
					t.Fatal(err)
				}
				requireConfigDecode(encoded)
			}
		})
	}
}

func TestHeaderRulesProgrammaticAliasConflict(t *testing.T) {
	t.Parallel()
	policy := HarpoonTargetTemplate{AllowedHeaders: []string{}, HeaderRules: []HarpoonHeaderRule{}}
	if _, err := policy.NormalizedHeaderRules(); err == nil {
		t.Fatal("programmatic empty aliases were accepted")
	}
	if _, err := yaml.Marshal(policy); err == nil {
		t.Fatal("YAML marshaling accepted conflicting aliases")
	}
	if _, err := json.Marshal(policy); err == nil {
		t.Fatal("JSON marshaling accepted conflicting aliases")
	}
}

func TestHeaderRulesYAMLAnchorsPreserveStrictness(t *testing.T) {
	t.Parallel()
	var policy HarpoonTargetTemplate
	if err := yaml.Unmarshal([]byte(`header_rules:
  - &rule
    name: X-First
    description: First header
    validation: &validation
      max_length: 64
  - <<: *rule
    name: X-Second
    validation: *validation
`), &policy); err != nil {
		t.Fatal(err)
	}
	rules, err := policy.NormalizedHeaderRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[1].Name != "X-Second" || rules[1].Description != "First header" || *rules[1].Validation.MaxLength != 64 {
		t.Fatal("YAML merge or anchor changed header rules")
	}
	if err := yaml.Unmarshal([]byte(`header_rules: &rules [Accept]
<<: {allowed_headers: *rules}
`), &policy); err == nil {
		t.Fatal("YAML merge bypassed alias conflict rejection")
	}
}
