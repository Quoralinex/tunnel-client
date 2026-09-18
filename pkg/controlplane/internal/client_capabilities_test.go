package internal

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openai/tunnel-client/pkg/clientcapabilities"
	"github.com/openai/tunnel-client/pkg/config"
	"github.com/openai/tunnel-client/pkg/controlplane/wiretypes"
	"github.com/openai/tunnel-client/pkg/tunnelctx"
	"github.com/openai/tunnel-client/pkg/types"
)

func TestClientCapabilitiesOnEveryControlPlaneOperation(t *testing.T) {
	t.Parallel()
	const commandToken = "legacy command,token"
	requests := make(chan string, 4)
	server := newHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, []string{clientcapabilities.WrongClusterV1}, r.Header.Values(clientcapabilities.HeaderName), "every control-plane request advertises implemented client capabilities")
		assert.Empty(t, r.Header.Values("X-Tunnel-Routing-Capability"))
		requests <- r.Method + " " + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/tunnels/capabilities/poll":
			assert.Empty(t, r.Header.Values(wiretypes.ShardTokenHeader), "the first poll advertises capability before learning any token")
			w.WriteHeader(http.StatusNoContent)
		case "/v1/tunnels/capabilities":
			assert.Empty(t, r.Header.Values(wiretypes.ShardTokenHeader))
			_, _ = w.Write([]byte(`{"id":"capabilities","name":"Capabilities"}`))
		case "/v1/tunnels/capabilities/cloudflare/runtime":
			assert.Empty(t, r.Header.Values(wiretypes.ShardTokenHeader))
			_, _ = w.Write([]byte(`{"cloudflare_tunnel":{"tunnel_id":"provider","name":"managed","account_id":"account","created_at":"2026-07-31T00:00:00Z"},"runtime_token":"fixture-token"}`))
		case "/v1/tunnels/capabilities/response":
			assert.Equal(t, commandToken, r.Header.Get(wiretypes.ShardTokenHeader), "capability emission must preserve the command's response token")
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected control-plane operation: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	client, err := NewTunnelServiceClient(t.Context(), &config.ControlPlaneConfig{
		BaseURL:  mustParseURL(t, server.URL),
		TunnelID: "capabilities",
		APIKey:   "fixture-api-key",
		ExtraHeaders: map[string]string{
			"x-tunnel-client-capabilities": "unimplemented-v1",
			"x-tunnel-shard-token":         "configuration-cannot-set-routing",
		},
	}, nil, newDiscardLogger(), &config.LoggingConfig{}, testMeterProvider)
	require.NoError(t, err)
	_, _, err = client.Poll(t.Context(), 1)
	require.NoError(t, err)
	_, err = client.FetchTunnelMetadata(t.Context())
	require.NoError(t, err)
	_, err = client.FetchManagedCloudflareTunnel(t.Context())
	require.NoError(t, err)
	ctx := tunnelctx.ContextWithShardToken(t.Context(), commandToken)
	ctx = tunnelctx.ContextWithChannel(ctx, types.DefaultChannel)
	_, err = client.PostResponse(ctx, "notification", types.NewNotificationAck(types.DefaultChannel, http.StatusOK, http.Header{}))
	require.NoError(t, err)
	require.Len(t, requests, 4)
	for _, want := range []string{
		"GET /v1/tunnels/capabilities/poll",
		"GET /v1/tunnels/capabilities",
		"GET /v1/tunnels/capabilities/cloudflare/runtime",
		"POST /v1/tunnels/capabilities/response",
	} {
		require.Equal(t, want, <-requests)
	}
}
