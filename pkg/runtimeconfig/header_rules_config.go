package runtimeconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// HarpoonHeaderRule allows one caller-supplied header. ForwardAs is private
// routing configuration and must never appear in public discovery metadata.
// The runtime compiler validates the complete policy before accepting calls.
type HarpoonHeaderRule struct {
	Name        string                   `yaml:"name" json:"name"`
	Description string                   `yaml:"description,omitempty" json:"description,omitempty"`
	Required    bool                     `yaml:"required,omitempty" json:"required,omitempty"`
	Credential  bool                     `yaml:"credential,omitempty" json:"credential,omitempty"`
	ForwardAs   string                   `yaml:"forward_as,omitempty" json:"forward_as,omitempty"`
	Validation  *HarpoonHeaderValidation `yaml:"validation,omitempty" json:"validation,omitempty"`
	// Legacy marks string shorthand, retaining its original value semantics.
	Legacy bool `yaml:"-" json:"-"`
}

// HarpoonHeaderValidation applies every configured constraint. Pointer lengths
// distinguish an explicitly configured zero from an omitted constraint.
type HarpoonHeaderValidation struct {
	Pattern   string   `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	Enum      []string `yaml:"enum,omitempty" json:"enum,omitempty"`
	MinLength *int     `yaml:"min_length,omitempty" json:"min_length,omitempty"`
	MaxLength *int     `yaml:"max_length,omitempty" json:"max_length,omitempty"`
}

// NormalizedHeaderRules returns a single policy representation for both config
// names. Setting both Go fields is ambiguous even when either list is empty.
func (t HarpoonTargetTemplate) NormalizedHeaderRules() ([]HarpoonHeaderRule, error) {
	if t.AllowedHeaders != nil && (t.HeaderRules != nil || t.headerRulesKey == "header_rules") {
		return nil, fmt.Errorf("header_rules and allowed_headers cannot be combined")
	}
	if t.HeaderRules != nil {
		return t.HeaderRules, nil
	}
	if t.AllowedHeaders == nil {
		return nil, nil
	}
	rules := make([]HarpoonHeaderRule, len(t.AllowedHeaders))
	for i, name := range t.AllowedHeaders {
		rules[i] = HarpoonHeaderRule{Name: name, Legacy: true}
	}
	return rules, nil
}

// These aliases omit custom marshal methods while retaining every template
// field, so adding another template option cannot silently drop it here.
type templateHeaderRuleFields HarpoonTargetTemplate
type headerRuleFields HarpoonHeaderRule

type templateHeaderRulesYAML struct {
	templateHeaderRuleFields `yaml:",inline"`
	AllowedHeaders           yaml.Node `yaml:"allowed_headers"`
	HeaderRules              yaml.Node `yaml:"header_rules"`
}

type templateHeaderRulesJSON struct {
	templateHeaderRuleFields
	AllowedHeaders json.RawMessage `json:"allowed_headers,omitempty"`
	HeaderRules    json.RawMessage `json:"header_rules,omitempty"`
}

func (t *HarpoonTargetTemplate) UnmarshalYAML(node *yaml.Node) error {
	var fields templateHeaderRulesYAML
	if err := decodeHeaderRulesYAML(node, &fields, validateTemplateHeaderRuleShapes); err != nil {
		return err
	}
	if fields.AllowedHeaders.Kind != 0 && fields.HeaderRules.Kind != 0 {
		return fmt.Errorf("header_rules and allowed_headers cannot be combined")
	}
	var rules []HarpoonHeaderRule
	key := ""
	switch {
	case fields.HeaderRules.Kind != 0:
		key = "header_rules"
		if err := decodeHeaderRuleListYAML(&fields.HeaderRules, &rules); err != nil {
			return err
		}
	case fields.AllowedHeaders.Kind != 0:
		key = "allowed_headers"
		if err := decodeHeaderRuleListYAML(&fields.AllowedHeaders, &rules); err != nil {
			return err
		}
	}
	*t = HarpoonTargetTemplate(fields.templateHeaderRuleFields)
	t.setHeaderRules(key, rules)
	return nil
}

func decodeHeaderRuleListYAML(node *yaml.Node, rules *[]HarpoonHeaderRule) error {
	if node.Tag == "!!null" {
		return fmt.Errorf("header rules cannot be null; omit the field or use an empty list")
	}
	if node.Kind != yaml.SequenceNode {
		return fmt.Errorf("cannot unmarshal header rules: expected a list")
	}
	for _, entry := range node.Content {
		if entry.Kind != yaml.MappingNode && (entry.Kind != yaml.ScalarNode || entry.Tag != "!!str") {
			return fmt.Errorf("header rule must be a string or an object")
		}
	}
	return node.Decode(rules)
}

func (t *HarpoonTargetTemplate) UnmarshalJSON(data []byte) error {
	var fields templateHeaderRulesJSON
	if err := decodeHeaderRulesJSON(data, &fields, validateTemplateHeaderRuleShapes); err != nil {
		return err
	}
	if fields.AllowedHeaders != nil && fields.HeaderRules != nil {
		return fmt.Errorf("header_rules and allowed_headers cannot be combined")
	}
	var rules []HarpoonHeaderRule
	key := ""
	switch {
	case fields.HeaderRules != nil:
		key = "header_rules"
		if bytes.Equal(bytes.TrimSpace(fields.HeaderRules), []byte("null")) {
			return fmt.Errorf("header rules cannot be null; omit the field or use an empty list")
		}
		if err := json.Unmarshal(fields.HeaderRules, &rules); err != nil {
			return err
		}
	case fields.AllowedHeaders != nil:
		key = "allowed_headers"
		if bytes.Equal(bytes.TrimSpace(fields.AllowedHeaders), []byte("null")) {
			return fmt.Errorf("header rules cannot be null; omit the field or use an empty list")
		}
		if err := json.Unmarshal(fields.AllowedHeaders, &rules); err != nil {
			return err
		}
	}
	*t = HarpoonTargetTemplate(fields.templateHeaderRuleFields)
	t.setHeaderRules(key, rules)
	return nil
}

func (t *HarpoonTargetTemplate) setHeaderRules(key string, rules []HarpoonHeaderRule) {
	if key == "allowed_headers" && rules != nil {
		legacy := true
		for _, rule := range rules {
			legacy = legacy && rule.Legacy
		}
		if legacy {
			t.AllowedHeaders = make([]string, len(rules))
			for i, rule := range rules {
				t.AllowedHeaders[i] = rule.Name
			}
			return
		}
	}
	t.HeaderRules = rules
	t.headerRulesKey = key
}

func (t HarpoonTargetTemplate) headerRulesForEncoding() (string, []HarpoonHeaderRule, error) {
	rules, err := t.NormalizedHeaderRules()
	if err != nil {
		return "", nil, err
	}
	key := t.headerRulesKey
	if key == "" {
		if t.HeaderRules != nil {
			key = "header_rules"
		} else if t.AllowedHeaders != nil {
			key = "allowed_headers"
		}
	}
	if key != "" && rules == nil {
		// A caller may clear a decoded list without changing its alias. Emit
		// an empty list, since explicit null is never a valid configuration.
		rules = []HarpoonHeaderRule{}
	}
	return key, rules, nil
}

func (t HarpoonTargetTemplate) MarshalYAML() (any, error) {
	key, rules, err := t.headerRulesForEncoding()
	if err != nil {
		return nil, err
	}
	fields := struct {
		templateHeaderRuleFields `yaml:",inline"`
		AllowedHeaders           any `yaml:"allowed_headers,omitempty"`
		HeaderRules              any `yaml:"header_rules,omitempty"`
	}{templateHeaderRuleFields: templateHeaderRuleFields(t)}
	switch key {
	case "header_rules":
		fields.HeaderRules = rules
	case "allowed_headers":
		fields.AllowedHeaders = rules
	}
	return fields, nil
}

func (t HarpoonTargetTemplate) MarshalJSON() ([]byte, error) {
	key, rules, err := t.headerRulesForEncoding()
	if err != nil {
		return nil, err
	}
	fields := templateHeaderRulesJSON{templateHeaderRuleFields: templateHeaderRuleFields(t)}
	if key != "" {
		encoded, err := json.Marshal(rules)
		if err != nil {
			return nil, err
		}
		if key == "header_rules" {
			fields.HeaderRules = encoded
		} else {
			fields.AllowedHeaders = encoded
		}
	}
	return json.Marshal(fields)
}

func (r *HarpoonHeaderRule) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
		*r = HarpoonHeaderRule{Name: node.Value, Legacy: true}
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("header rule must be a string or an object")
	}
	var fields headerRuleFields
	if err := decodeHeaderRulesYAML(node, &fields, validateHeaderRuleShape); err != nil {
		return err
	}
	*r = HarpoonHeaderRule(fields)
	return nil
}

func (r *HarpoonHeaderRule) UnmarshalJSON(data []byte) error {
	var name string
	if len(data) != 0 && data[0] == '"' {
		if err := json.Unmarshal(data, &name); err != nil {
			return err
		}
		*r = HarpoonHeaderRule{Name: name, Legacy: true}
		return nil
	}
	if len(data) == 0 || data[0] != '{' {
		return fmt.Errorf("header rule must be a string or an object")
	}
	var fields headerRuleFields
	if err := decodeHeaderRulesJSON(data, &fields, validateHeaderRuleShape); err != nil {
		return err
	}
	*r = HarpoonHeaderRule(fields)
	return nil
}

func (r HarpoonHeaderRule) MarshalYAML() (any, error) {
	if r.Legacy {
		return r.Name, nil
	}
	return headerRuleFields(r), nil
}

func (r HarpoonHeaderRule) MarshalJSON() ([]byte, error) {
	if r.Legacy {
		return json.Marshal(r.Name)
	}
	return json.Marshal(headerRuleFields(r))
}

// Node.Decode does not inherit the parent decoder's KnownFields setting. Expand
// YAML anchors first, retaining duplicate-key rejection, then use a strict
// decoder so custom header parsing cannot weaken the surrounding config schema.
func decodeHeaderRulesYAML(node *yaml.Node, value any, validateShape func(any) error) error {
	var expanded any
	if err := node.Decode(&expanded); err != nil {
		return err
	}
	if err := validateShape(expanded); err != nil {
		return err
	}
	data, err := yaml.Marshal(expanded)
	if err != nil {
		return err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	return decoder.Decode(value)
}

func decodeHeaderRulesJSON(data []byte, value any, validateShape func(any) error) error {
	// JSON's ordinary decoder accepts duplicate object keys. The YAML decoder
	// rejects them, including duplicates nested inside validation constraints.
	var duplicateCheck any
	if err := yaml.Unmarshal(data, &duplicateCheck); err != nil {
		return err
	}
	if err := validateShape(duplicateCheck); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("exactly one JSON value is required")
	}
	return nil
}

// Validate the expanded values before typed decoding: yaml.v3 otherwise
// converts numbers and booleans to strings and truncates fractional integers.
// Null constraints must fail rather than silently becoming omitted checks.
func validateTemplateHeaderRuleShapes(value any) error {
	fields, ok := value.(map[string]any)
	if !ok {
		return nil // The typed decoder reports malformed template objects.
	}
	_, hasRules := fields["header_rules"]
	_, hasAllowed := fields["allowed_headers"]
	if hasRules && hasAllowed {
		return fmt.Errorf("header_rules and allowed_headers cannot be combined")
	}
	for _, key := range []string{"header_rules", "allowed_headers"} {
		raw, exists := fields[key]
		if !exists {
			continue
		}
		if raw == nil {
			return fmt.Errorf("header rules cannot be null; omit the field or use an empty list")
		}
		entries, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("cannot unmarshal header rules: expected a list")
		}
		for _, entry := range entries {
			if _, isString := entry.(string); isString {
				continue
			}
			if err := validateHeaderRuleShape(entry); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateHeaderRuleShape(value any) error {
	fields, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("header rule must be a string or an object")
	}
	for name, value := range fields {
		switch name {
		case "name", "description", "forward_as":
			if _, ok := value.(string); !ok {
				return fmt.Errorf("cannot unmarshal header rule field %q: expected a string", name)
			}
		case "required", "credential":
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("cannot unmarshal header rule field %q: expected a boolean", name)
			}
		case "validation":
			if err := validateHeaderValidationShape(value); err != nil {
				return err
			}
		default:
			return fmt.Errorf("field %s not found in header rule", name)
		}
	}
	return nil
}

func validateHeaderValidationShape(value any) error {
	fields, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("cannot unmarshal header rule validation: expected an object")
	}
	for name, value := range fields {
		switch name {
		case "pattern":
			if _, ok := value.(string); !ok {
				return fmt.Errorf("cannot unmarshal header validation pattern: expected a string")
			}
		case "enum":
			entries, ok := value.([]any)
			if !ok {
				return fmt.Errorf("cannot unmarshal header validation enum: expected a string list")
			}
			for _, entry := range entries {
				if _, ok := entry.(string); !ok {
					return fmt.Errorf("cannot unmarshal header validation enum: expected string entries")
				}
			}
		case "min_length", "max_length":
			switch value.(type) {
			case int, int64, uint64:
				// Typed decoding still checks whether the integer fits in int.
			default:
				return fmt.Errorf("cannot unmarshal header validation %s: expected an integer", name)
			}
		default:
			return fmt.Errorf("field %s not found in header validation", name)
		}
	}
	return nil
}
