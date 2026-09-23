package runtimeharpoon

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
)

const maxTemplateBodyBytes = 100 * 1024

type compiledTemplateBodyPolicy struct {
	schema  runtimeconfig.HarpoonTemplateBodyPolicy
	pattern *regexp.Regexp
}

func compileTemplateBodyPolicy(method string, cfg *runtimeconfig.HarpoonTemplateBodyPolicy) (*compiledTemplateBodyPolicy, error) {
	if method == http.MethodGet {
		if cfg != nil {
			return nil, errors.New("template GET cannot configure a body policy")
		}
		return nil, nil
	}
	if cfg == nil || cfg.Validation == nil || cfg.Required == nil {
		return nil, errors.New("template writes require an explicit body policy, required setting, and validation")
	}
	if cfg.MaxBytes <= 0 || cfg.MaxBytes > maxTemplateBodyBytes {
		return nil, errors.New("template body byte limit must be within 1 to 102400")
	}
	if len(cfg.ContentTypes) == 0 || len(cfg.ContentTypes) > 16 {
		return nil, errors.New("template body policy must allow 1 to 16 content types")
	}
	validation := *cfg.Validation
	if !validation.JSON && validation.Pattern == "" && len(validation.Enum) == 0 {
		return nil, errors.New("template body policy requires JSON, pattern, or enum validation")
	}
	if len(validation.Pattern) > maxTemplatePattern || len(validation.Enum) > maxTemplateEnumValues {
		return nil, errors.New("template body validation exceeds size limits")
	}
	p := &compiledTemplateBodyPolicy{schema: *cfg}
	required := *cfg.Required
	p.schema.Required = &required
	p.schema.ContentTypes = slices.Clone(cfg.ContentTypes)
	validation.Enum = slices.Clone(validation.Enum)
	p.schema.Validation = &validation
	seen := make(map[string]struct{}, len(cfg.ContentTypes))
	for _, contentType := range cfg.ContentTypes {
		mediaType, params, err := mime.ParseMediaType(contentType)
		if err != nil || mediaType != contentType || len(params) != 0 || strings.Contains(contentType, "*") || len(contentType) > 128 || !strings.Contains(contentType, "/") {
			return nil, errors.New("template content types must be canonical media types without parameters or wildcards")
		}
		if (contentType == "application/json" || strings.HasSuffix(contentType, "+json")) && !validation.JSON {
			return nil, errors.New("JSON content types require JSON body validation")
		}
		if _, duplicate := seen[contentType]; duplicate {
			return nil, errors.New("duplicate template content type")
		}
		seen[contentType] = struct{}{}
	}
	if validation.Pattern != "" {
		if err := validateTemplateBodyPattern(validation.Pattern); err != nil {
			return nil, errors.New("unsupported template body pattern")
		}
		pattern, err := regexp.Compile(`\A(?:` + validation.Pattern + `)\z`)
		if err != nil {
			return nil, errors.New("invalid template body pattern")
		}
		p.pattern = pattern
	}
	seen = make(map[string]struct{}, len(validation.Enum))
	total := 0
	for _, value := range validation.Enum {
		total += len(value)
		if total > maxTemplateBodyBytes || p.validate(&value, &cfg.ContentTypes[0]) != nil {
			return nil, errors.New("template body enum violates body policy or size limits")
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, errors.New("duplicate template body enum value")
		}
		seen[value] = struct{}{}
	}
	return p, nil
}

// Body patterns can consume only printable ASCII. Unlike identifier values,
// bodies otherwise allow arbitrary UTF-8, exposing differences in shorthand
// classes, line terminators, and rune/UTF-16 quantifiers across schema consumers.
func validateTemplateBodyPattern(pattern string) error {
	if err := validateTemplatePattern(pattern); err != nil {
		return err
	}
	inClass := false
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++ // The shared validator already checked the escape is complete.
			if strings.ContainsRune(`dDsSwW`, rune(pattern[i])) || pattern[i] == '-' && !inClass {
				return errors.New("body patterns require explicit ASCII classes and escaped syntax punctuation")
			}
		case '[':
			if inClass || i+1 < len(pattern) && pattern[i+1] == '^' {
				return errors.New("body patterns cannot use nested or negated classes")
			}
			inClass = true
		case ']':
			if !inClass {
				return errors.New("body patterns must escape literal closing brackets")
			}
			inClass = false
		case '.':
			if !inClass {
				return errors.New("body patterns cannot use wildcard dots")
			}
		case '^', '$':
			if !inClass && i+1 < len(pattern) && strings.ContainsRune(`*+?{`, rune(pattern[i+1])) {
				return errors.New("body patterns cannot quantify anchors directly")
			}
		case '{':
			if inClass {
				continue
			}
			start := i + 1
			for i++; i < len(pattern) && pattern[i] >= '0' && pattern[i] <= '9'; i++ {
			}
			if i == start || i-start > 1 && pattern[start] == '0' {
				return errors.New("body patterns must escape literal opening braces")
			}
			if i < len(pattern) && pattern[i] == ',' {
				start = i + 1
				for i++; i < len(pattern) && pattern[i] >= '0' && pattern[i] <= '9'; i++ {
				}
				if i-start > 1 && pattern[start] == '0' {
					return errors.New("body patterns cannot use leading zeros in repetition bounds")
				}
			}
			if i >= len(pattern) || pattern[i] != '}' {
				return errors.New("body patterns require valid repetition bounds")
			}
		case '}':
			if !inClass {
				return errors.New("body patterns must escape literal closing braces")
			}
		}
	}
	return nil
}

func (p *compiledTemplateBodyPolicy) validate(body, contentType *string) error {
	if p == nil {
		if body != nil || contentType != nil {
			return errors.New("template GET requests cannot contain body or content_type arguments")
		}
		return nil
	}
	if body == nil && contentType == nil && !*p.schema.Required {
		return nil
	}
	if body == nil || contentType == nil {
		return errors.New("template body and content_type must be supplied together")
	}
	if !slices.Contains(p.schema.ContentTypes, *contentType) {
		return errors.New("template content type is not permitted")
	}
	if len(*body) > p.schema.MaxBytes || *p.schema.Required && len(*body) == 0 || !utf8.ValidString(*body) {
		return errors.New("template body violates its byte limit or required-body policy")
	}
	validation := p.schema.Validation
	if validation.JSON && (!json.Valid([]byte(*body)) || !validTemplateJSONStrings([]byte(*body))) {
		return errors.New("template body must be valid JSON")
	}
	if p.pattern != nil && !p.pattern.MatchString(*body) {
		return errors.New("template body does not match its pattern")
	}
	if len(validation.Enum) > 0 && !slices.Contains(validation.Enum, *body) {
		return errors.New("template body is outside its enum")
	}
	return nil
}

// encoding/json replaces malformed UTF-8 and unpaired escaped UTF-16 surrogates
// with U+FFFD. Reject those inputs before decoding to preserve payload bytes.
func validTemplateJSONStrings(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	quoted := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		value, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if value >= 0xdc00 && value <= 0xdfff {
			return false
		}
		if value >= 0xd800 && value <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

func (p *compiledTemplateBodyPolicy) publicPolicy() *runtimeconfig.HarpoonTemplateBodyPolicy {
	if p == nil {
		return nil
	}
	policy := p.schema
	required := *policy.Required
	policy.Required = &required
	policy.ContentTypes = slices.Clone(policy.ContentTypes)
	validation := *policy.Validation
	validation.Enum = slices.Clone(validation.Enum)
	policy.Validation = &validation
	return &policy
}

func (p *compiledTemplateBodyPolicy) canonicalPolicy() *runtimeconfig.HarpoonTemplateBodyPolicy {
	policy := p.publicPolicy()
	if policy != nil {
		sort.Strings(policy.ContentTypes)
		sort.Strings(policy.Validation.Enum)
	}
	return policy
}

// Recheck the body at the outbound boundary, including its exact original bytes.
// Replacing the reader preserves a single-use request: GetBody remains nil even
// for empty writes, so net/http cannot replay a write after an ambiguous failure.
func (t *TargetTemplate) validateRequestBody(req *http.Request, body, contentType *string) error {
	if err := t.bodyPolicy.validate(body, contentType); err != nil {
		return err
	}
	if t.method == http.MethodGet {
		if req.Body != nil && req.Body != http.NoBody || req.ContentLength != 0 || len(req.TransferEncoding) != 0 || len(req.Trailer) != 0 {
			return errors.New("template GET requests cannot contain a body")
		}
		return nil
	}
	if len(req.TransferEncoding) != 0 || len(req.Trailer) != 0 || req.GetBody != nil || req.Body == nil || req.Body == http.NoBody {
		return errors.New("template write requires a single-use body")
	}
	expected := ""
	if body != nil {
		expected = *body
	}
	if req.ContentLength != int64(len(expected)) {
		return errors.New("outbound body length does not match the template invocation")
	}
	actual, err := io.ReadAll(io.LimitReader(req.Body, int64(len(expected))+1))
	_ = req.Body.Close()
	if err != nil || !bytes.Equal(actual, []byte(expected)) {
		return errors.New("outbound body does not match the template invocation")
	}
	req.Body = io.NopCloser(bytes.NewReader(actual))
	if contentType == nil {
		if _, present := req.Header["Content-Type"]; present {
			return errors.New("outbound content type does not match the template invocation")
		}
	} else if req.Header.Get("Content-Type") != *contentType {
		return errors.New("outbound content type does not match the template invocation")
	}
	return nil
}
