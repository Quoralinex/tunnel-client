package runtimeharpoon

import (
	"errors"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
)

// The compiled maps are keyed separately by public source and private outgoing
// name. Keeping the latter out of the public projection prevents a rename from
// revealing the destination's authentication or routing convention.
type compiledTemplateHeaderRule struct {
	schema  runtimeconfig.HarpoonHeaderRule
	pattern *regexp.Regexp
}

func (t *TargetTemplate) compileHeaderRules(rules []runtimeconfig.HarpoonHeaderRule) error {
	t.headerRules = make(map[string]compiledTemplateHeaderRule, len(rules))
	t.headerDestinations = make(map[string]compiledTemplateHeaderRule, len(rules))
	for _, rule := range rules {
		source, err := canonicalTemplateHeader(rule.Name)
		if err != nil {
			return err
		}
		destination := source
		if rule.ForwardAs != "" {
			destination, err = canonicalTemplateHeader(rule.ForwardAs)
			if err != nil {
				return err
			}
		}
		if rule.Legacy && (rule.Description != "" || rule.ForwardAs != "" || rule.Required || rule.Credential || rule.Validation != nil) {
			return errors.New("legacy template header rules cannot include structured settings")
		}
		if !rule.Legacy && (strings.TrimSpace(rule.Description) == "" || len(rule.Description) > maxTemplateDescription || !validTemplateText(rule.Description)) {
			return errors.New("template header rules require a bounded nonempty description")
		}
		for _, name := range []string{source, destination} {
			if !rule.Legacy && isReservedRichTemplateHeader(name) {
				return errors.New("reserved transport or identity header cannot be a runtime rule")
			}
			if t.bodyPolicy != nil && (name == "Content-Type" || name == "Content-Encoding") {
				return errors.New("template writes require the body policy content type and unencoded body bytes")
			}
			if _, exists := t.headers[name]; exists {
				return errors.New("template caller header conflicts with a fixed header")
			}
			if isTemplateCredentialHeader(name) && (!rule.Credential || !supportedTemplateCredentialHeader(name)) {
				return errors.New("template authentication headers must be fixed by the operator or explicitly supported by a credential rule")
			}
		}
		if rule.Credential && !supportedTemplateCredentialHeader(source) && !supportedTemplateCredentialHeader(destination) {
			return errors.New("template credential rule must use a supported credential header")
		}
		if _, exists := t.headerRules[source]; exists {
			return errors.New("duplicate template caller header name")
		}
		if _, exists := t.headerDestinations[destination]; exists {
			return errors.New("duplicate template outgoing header name")
		}
		rule.Name, rule.ForwardAs = source, destination
		compiled, err := compileTemplateHeaderValidation(rule)
		if err != nil {
			return err
		}
		t.headerRules[source], t.headerDestinations[destination] = compiled, compiled
	}
	for source, rule := range t.headerRules {
		if source != rule.schema.ForwardAs {
			if _, exists := t.headerRules[rule.schema.ForwardAs]; exists {
				return errors.New("template header source and destination names overlap")
			}
		}
	}
	return nil
}

// Retain the legacy allowlist's existing predicate. Structured rules also
// reserve these protocol namespaces, including when used through a rename.
func isReservedRichTemplateHeader(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"proxy-", "mcp-", "x-mcp-", "x-tunnel-", "x-openai-"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func supportedTemplateCredentialHeader(name string) bool {
	switch strings.ToLower(name) {
	case "authorization", "x-api-key", "api-key":
		return true
	default:
		return false
	}
}

func compileTemplateHeaderValidation(rule runtimeconfig.HarpoonHeaderRule) (compiledTemplateHeaderRule, error) {
	compiled := compiledTemplateHeaderRule{schema: rule}
	if rule.Credential {
		// Validation metadata is public discovery. A credential enum would
		// disclose the accepted secret values, even when a pattern is also set.
		if rule.Validation != nil && rule.Validation.Enum != nil {
			return compiled, errors.New("template credential rules cannot configure enum values")
		}
		if rule.Validation == nil || rule.Validation.MinLength == nil || rule.Validation.MaxLength == nil || *rule.Validation.MinLength <= 0 || *rule.Validation.MaxLength <= 0 || rule.Validation.Pattern == "" {
			return compiled, errors.New("template credential rules require positive length bounds and a pattern")
		}
	}
	if rule.Validation == nil {
		return compiled, nil
	}
	validation := *rule.Validation
	validation.Enum = slices.Clone(validation.Enum)
	if validation.Enum != nil && len(validation.Enum) == 0 {
		return compiled, errors.New("template header enum must not be empty")
	}
	minimum, maximum := 0, maxTemplateHeaderBytes
	if validation.MinLength != nil {
		minimum = *validation.MinLength
		validation.MinLength = &minimum
	}
	if validation.MaxLength != nil {
		maximum = *validation.MaxLength
		validation.MaxLength = &maximum
	}
	if minimum < 0 || maximum < minimum || maximum > maxTemplateHeaderBytes {
		return compiled, errors.New("template header length bounds must be within 0 to 8192")
	}
	if len(validation.Pattern) > maxTemplatePattern || len(validation.Enum) > maxTemplateEnumValues {
		return compiled, errors.New("template header constraints exceed size limits")
	}
	compiled.schema.Validation = &validation
	if validation.Pattern != "" {
		// Reuse the strict portable ASCII subset already enforced for request
		// bodies. Values with a pattern must also be printable ASCII.
		if err := validateTemplateBodyPattern(validation.Pattern); err != nil {
			return compiled, errors.New("unsupported template header pattern")
		}
		pattern, err := regexp.Compile(`\A(?:` + validation.Pattern + `)\z`)
		if err != nil {
			return compiled, errors.New("invalid template header pattern")
		}
		compiled.pattern = pattern
	}
	seen, size := make(map[string]struct{}, len(validation.Enum)), 0
	for _, value := range validation.Enum {
		size += len(value)
		if size > maxTemplateHeaderBytes || compiled.validate(value) != nil {
			return compiled, errors.New("template header enum violates its constraints or size limits")
		}
		if _, exists := seen[value]; exists {
			return compiled, errors.New("duplicate template header enum value")
		}
		seen[value] = struct{}{}
	}
	return compiled, nil
}

func (r compiledTemplateHeaderRule) validate(value string) error {
	if !validTemplateHeaderValue(value) {
		return errors.New("invalid caller header value")
	}
	validation := r.schema.Validation
	if validation == nil {
		return nil
	}
	length := utf8.RuneCountInString(value)
	if validation.MinLength != nil && length < *validation.MinLength || validation.MaxLength != nil && length > *validation.MaxLength {
		return errors.New("caller header length is outside its bounds")
	}
	if r.pattern != nil {
		for _, c := range value {
			if c < 0x20 || c > 0x7e {
				return errors.New("caller header pattern requires printable ASCII")
			}
		}
		if !r.pattern.MatchString(value) {
			return errors.New("caller header does not match its pattern")
		}
	}
	if len(validation.Enum) > 0 && !slices.Contains(validation.Enum, value) {
		return errors.New("caller header is outside its enum")
	}
	return nil
}

// HasRichHeaderRules identifies targets that require a discovered policy-bound
// invocation. String-only allowlists keep the original invocation contract.
func (t *TargetTemplate) HasRichHeaderRules() bool {
	if t != nil {
		for _, rule := range t.headerRules {
			if !rule.schema.Legacy {
				return true
			}
		}
	}
	return false
}

// Only structured-policy calls add stable public error codes; legacy callers
// retain their existing error text. Details never contain supplied values or
// private outgoing names.
func (t *TargetTemplate) headerError(code string, err error) error {
	if t.HasRichHeaderRules() {
		return errors.New(code + ": " + err.Error())
	}
	return err
}

// canonicalHeaderRules belongs only in the private policy digest. It includes
// renames, credential handling, requiredness, and every validation constraint.
func (t *TargetTemplate) canonicalHeaderRules() []runtimeconfig.HarpoonHeaderRule {
	rules := make([]runtimeconfig.HarpoonHeaderRule, 0, len(t.headerRules))
	for _, rule := range t.headerRules {
		copy := rule.schema
		if copy.Validation != nil {
			validation := *copy.Validation
			validation.Enum = slices.Clone(validation.Enum)
			sort.Strings(validation.Enum)
			copy.Validation = &validation
		}
		rules = append(rules, copy)
	}
	slices.SortFunc(rules, func(a, b runtimeconfig.HarpoonHeaderRule) int { return strings.Compare(a.Name, b.Name) })
	return rules
}

// templateHeadersSchema is the single public projection used by tools/list and
// list_targets. It intentionally never serializes the private rule object.
func (t *TargetTemplate) templateHeadersSchema() (map[string]any, bool) {
	properties := make(map[string]any, len(t.headerRules))
	var required []string
	for name, rule := range t.headerRules {
		property := map[string]any{
			"type": "string", "maxLength": maxTemplateHeaderBytes,
			"not": map[string]any{"pattern": "[\x00-\x1f\x7f]"},
		}
		if rule.schema.Description != "" {
			property["description"] = rule.schema.Description
		}
		if validation := rule.schema.Validation; validation != nil {
			if validation.MinLength != nil {
				property["minLength"] = *validation.MinLength
			}
			if validation.MaxLength != nil {
				property["maxLength"] = *validation.MaxLength
			}
			// Compilation rejects credential enums. Retain this explicit public
			// projection boundary so malformed internal policy cannot expose one.
			if !rule.schema.Credential && len(validation.Enum) > 0 {
				property["enum"] = slices.Clone(validation.Enum)
			}
			if validation.Pattern != "" {
				property["pattern"] = "^(?:" + validation.Pattern + ")$"
				property["not"] = map[string]any{"pattern": "[^ -~]"}
			}
		}
		if rule.schema.Required {
			required = append(required, name)
		}
		properties[name] = property
	}
	sort.Strings(required)
	schema := map[string]any{
		"type": "object", "properties": properties, "additionalProperties": false,
		"maxProperties": maxTemplateHeaders,
		"description":   "Caller headers using the advertised spelling; runtime names are case-insensitive. Values must be valid UTF-8 without control characters. Pattern-bearing rules require printable ASCII; length bounds count Unicode code points. The client also enforces an 8192-byte total header budget including managed headers.",
	}
	if len(required) > 0 {
		schema["required"] = required
	} else {
		schema["default"] = map[string]string{}
	}
	return schema, len(required) > 0
}

// validateCallerHeaderBudget checks both input names and renamed output names;
// neither spelling may circumvent the existing aggregate byte budget.
func (t *TargetTemplate) validateCallerHeaderBudget(headers http.Header) error {
	combined := t.FixedHeaders()
	maps.Copy(combined, headers)
	return validateTemplateHeaderSize(combined)
}
