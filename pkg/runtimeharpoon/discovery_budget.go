package runtimeharpoon

import (
	"encoding/json"
	"math"
	"strings"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
)

// Bound catalogs opting into structured header rules well below the tunnel
// response limit, including the duplicated JSON text in list_targets. Reserve
// space for fixed tool schemas, MCP envelopes and response metadata. Unrelated
// tools added by registrars do not contribute to this catalog budget.
const maxTemplateDiscoveryBytes = 512 * 1024
const templateDiscoveryEnvelopeReserve = 64 * 1024
const maxTemplateCatalogBytes = maxTemplateDiscoveryBytes - templateDiscoveryEnvelopeReserve

// Registration does not depend on server configuration or a binding key. The
// largest integer bounds and a same-length placeholder digest conservatively
// size the exact public projection for every server configuration.
var discoveryBudgetInputSchema = buildTemplateCallInputSchema(&runtimeconfig.HarpoonConfig{
	MaxResponseBytes: math.MaxInt,
	MaxRedirects:     math.MaxInt,
})

func targetPublicInfo(target Target, invocation *targetInvocation) targetInfo {
	info := targetInfo{
		Label: target.Label, Description: target.Description,
		Category: target.Category, Source: target.Source, Tags: target.Tags,
		AllowedMethods: allowedMethodsList(),
	}
	if target.template != nil {
		info.AllowedMethods = []string{target.template.method}
		info.TemplateVersion = 1
		info.ParametersSchema = templateParametersSchema(target.template)
		info.Invocation = invocation
	}
	return info
}

func targetDiscoveryBytes(target Target) (int, error) {
	var invocation *targetInvocation
	if target.template != nil {
		label := target.Label
		if target.template.HasRichHeaderRules() {
			label = headerRuleInvocationPrefix + strings.Repeat("0", 64) + ":" + label
		}
		invocation = templateInvocationForLabel(target, label, discoveryBudgetInputSchema)
	}
	payload, err := json.Marshal(targetPublicInfo(target, invocation))
	if err != nil {
		return 0, err
	}
	if len(payload) > maxTemplateCatalogBytes {
		return maxTemplateCatalogBytes + 1, nil
	}
	escaped, err := json.Marshal(string(payload))
	if err != nil {
		return 0, err
	}
	// list_targets carries both a structured catalog and its JSON string. The
	// string's two surrounding quotes cover the two per-target array commas.
	// tools/list only includes each rich invocation's input_schema, a subset
	// of the structured target, so this also bounds its growing branches. Its
	// one generic legacy branch fits in the fixed envelope reserve.
	return min(maxTemplateCatalogBytes+1, len(payload)+len(escaped)), nil
}
