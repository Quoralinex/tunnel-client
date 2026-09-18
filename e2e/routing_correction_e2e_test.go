package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/openai/tunnel-client/pkg/clientcapabilities"
	"github.com/openai/tunnel-client/pkg/controlplane/wiretypes"
	harnesspkg "github.com/openai/tunnel-client/testsupport/e2e"
	"github.com/openai/tunnel-client/testsupport/mockmcpserver"
	"github.com/openai/tunnel-client/testsupport/mocktunnelservice"
)

// These ordered exchanges drive the actual client poller and dispatcher through
// a fake service. A zero response status resumes ordinary command delivery.
type routingPollExchange struct {
	requestToken string
	status       int
	token        string
	revision     int
}

func TestRoutingCorrectionRealClientSequences(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		exchanges []routingPollExchange
	}{
		{
			name: "old service accepts new client",
			exchanges: []routingPollExchange{
				{status: http.StatusNoContent},
				{},
			},
		},
		{
			name: "bootstrap and empty successes retain token",
			exchanges: []routingPollExchange{
				{status: http.StatusConflict, token: "placement-a", revision: 42},
				{requestToken: "placement-a", status: http.StatusNoContent},
				{requestToken: "placement-a", status: http.StatusOK},
				{requestToken: "placement-a"},
			},
		},
		{
			name: "dead cached destination and unavailable bootstrap recover",
			exchanges: []routingPollExchange{
				{status: http.StatusConflict, token: "placement-a", revision: 42},
				{requestToken: "placement-a", status: http.StatusNoContent},
				{requestToken: "placement-a", status: http.StatusServiceUnavailable},
				{requestToken: "placement-a", status: http.StatusServiceUnavailable},
				{requestToken: "placement-a", status: http.StatusServiceUnavailable},
				{status: http.StatusServiceUnavailable},
				{status: http.StatusConflict, token: "placement-b", revision: 43},
				{requestToken: "placement-b"},
			},
		},
		{
			name: "repeated corrections require tokenless recovery",
			exchanges: []routingPollExchange{
				{status: http.StatusConflict, token: "placement-a", revision: 42},
				{requestToken: "placement-a", status: http.StatusConflict, token: "placement-a", revision: 42},
				{requestToken: "placement-a", status: http.StatusConflict, token: "placement-a", revision: 42},
				{status: http.StatusConflict, token: "placement-b", revision: 43},
				{requestToken: "placement-b"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var mu sync.Mutex
			next := 0
			h := runSimpleToolScenarioWithHarnessOptions(t, nil, []mocktunnelservice.Option{
				mocktunnelservice.WithSessionHeaderPropagation(),
				mocktunnelservice.WithInitializationPhaseCommands(),
				mocktunnelservice.WithPollHandler(func(w http.ResponseWriter, r *http.Request) bool {
					mu.Lock()
					defer mu.Unlock()
					index := next
					if index >= len(tc.exchanges) {
						index = len(tc.exchanges) - 1
					} else {
						next++
					}
					exchange := tc.exchanges[index]
					if got := r.Header.Get(wiretypes.ShardTokenHeader); got != exchange.requestToken {
						t.Errorf("poll %d token = %q, want %q", index, got, exchange.requestToken)
					}
					if got := r.Header.Values(clientcapabilities.HeaderName); len(got) != 1 || got[0] != clientcapabilities.WrongClusterV1 {
						t.Errorf("poll %d capability = %v", index, got)
					}
					switch exchange.status {
					case 0:
						return false
					case http.StatusConflict:
						return writeFakeRoutingCorrection(w, r, exchange.token, exchange.revision)
					case http.StatusOK:
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(`{"commands":[]}`))
					default:
						w.WriteHeader(exchange.status)
					}
					return true
				}),
			})
			mu.Lock()
			require.Equal(t, len(tc.exchanges), next, "complete routing sequence must execute")
			mu.Unlock()
			assertNoTunnelMutationRequests(t, h.ControlPlane.ReceivedHTTPRequests())
		})
	}
}

func TestRoutingCorrectionPreservesInFlightCommandToken(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	const commandToken = "legacy-command-token"
	toolStarted := make(chan struct{})
	routeAccepted := make(chan struct{})
	var acceptedOnce sync.Once

	h := harnesspkg.NewHarness(t,
		harnesspkg.WithControlPlaneOptions(
			mocktunnelservice.WithSessionHeaderPropagation(),
			mocktunnelservice.WithInitializationPhaseCommands(),
			mocktunnelservice.WithPollHandler(func(w http.ResponseWriter, r *http.Request) bool {
				switch r.Header.Get(wiretypes.ShardTokenHeader) {
				case "":
					return writeFakeRoutingCorrection(w, r, "placement-a", 42)
				case "placement-a":
					select {
					case <-toolStarted:
						return writeFakeRoutingCorrection(w, r, "placement-b", 43)
					default:
						return false
					}
				case "placement-b":
					acceptedOnce.Do(func() { close(routeAccepted) })
					return false
				default:
					t.Errorf("unexpected polling token")
					w.WriteHeader(http.StatusBadRequest)
					return true
				}
			}),
			mocktunnelservice.WithCommandResponses(mocktunnelservice.CommandResponse{
				Command: mocktunnelservice.NewCommand(commandToken, json.RawMessage(`{
					"jsonrpc":"2.0","id":"in-flight","method":"tools/call",
					"params":{"name":"echo","arguments":{}}
				}`), http.Header{"Accept": {"application/json, text/event-stream"}}),
				ExpectedResponses: []mocktunnelservice.ExpectedResponse{
					{RequestID: commandToken, Assert: func(tb testing.TB, response mocktunnelservice.ReceivedResponse) {
						require.Equal(tb, string(wiretypes.ResponsePayloadJSONRPCNotify), response.ResponseType)
						require.Equal(tb, http.StatusOK, response.ResponseCode)
					}},
					{RequestID: commandToken, Assert: func(tb testing.TB, response mocktunnelservice.ReceivedResponse) {
						require.Equal(tb, string(wiretypes.ResponsePayloadJSONRPC), response.ResponseType)
						require.Equal(tb, http.StatusOK, response.ResponseCode)
					}},
				},
			}),
		),
		harnesspkg.WithMCPOptions(mockmcpserver.WithCalls(mockmcpserver.Call{
			Tool: "echo",
			DynamicResult: func(json.RawMessage) (json.RawMessage, error) {
				close(toolStarted)
				select {
				case <-routeAccepted:
					return json.RawMessage(`{"message":"done after reassignment"}`), nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			},
			Progress: []mockmcpserver.ProgressUpdate{{Percentage: 1, Message: "completed"}},
		})),
	)
	h.ExecuteScenarious(t)
	require.Len(t, h.MCP.ReceivedRequests(), 1, "routing must not replay tool execution")
	require.Len(t, h.ControlPlane.DeliveredCommands(), 3, "initialization and one tool command")
	requests := h.ControlPlane.ReceivedHTTPRequests()
	assertNoTunnelMutationRequests(t, requests)
	commandPosts := 0
	for _, request := range requests {
		if request.Method != http.MethodPost {
			continue
		}
		token := request.Headers.Get(wiretypes.ShardTokenHeader)
		require.NotContains(t, []string{"placement-a", "placement-b"}, token, "responses cannot use polling state")
		if token == commandToken {
			commandPosts++
		}
	}
	require.Equal(t, 2, commandPosts, "notification and terminal response must both echo the original token")
}

func TestRoutingCorrectionCancellationDuringBackoff(t *testing.T) {
	t.Parallel()
	h := harnesspkg.NewHarness(t,
		harnesspkg.WithControlPlaneOptions(mocktunnelservice.WithPollHandler(func(w http.ResponseWriter, r *http.Request) bool {
			w.Header().Set("Retry-After", "60")
			return writeFakeRoutingCorrection(w, r, "placement-a", 42)
		})),
		harnesspkg.WithAfterClientStart(func(h *harnesspkg.Harness) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			for {
				changed := h.PollHealth.Changes()
				if h.PollHealth.Snapshot(time.Now()).State == "backoff" {
					return
				}
				select {
				case <-changed:
				case <-ctx.Done():
					t.Fatal("routing correction did not enter cancellable backoff")
				}
			}
		}),
	)
	h.ExecuteScenarious(t)
	require.Equal(t, "stopped", h.PollHealth.Snapshot(time.Now()).State)
	polls := 0
	for _, request := range h.ControlPlane.ReceivedHTTPRequests() {
		if strings.HasSuffix(request.Path, "/poll") {
			polls++
		}
	}
	require.Equal(t, 1, polls, "shutdown must cancel backoff without another poll")
}

func TestRoutingCorrectionNewClientStartsTokenless(t *testing.T) {
	t.Parallel()
	h := harnesspkg.NewHarness(t,
		harnesspkg.WithControlPlaneOptions(mocktunnelservice.WithPollHandler(func(w http.ResponseWriter, r *http.Request) bool {
			if r.Header.Get(wiretypes.ShardTokenHeader) == "" {
				return writeFakeRoutingCorrection(w, r, "placement-a", 42)
			}
			return false
		})),
		harnesspkg.WithAfterClientStart(func(h *harnesspkg.Harness) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			waitForToken := func(client *harnesspkg.TunnelClient) {
				require.NoError(t, h.ControlPlane.WaitForHTTPRequests(ctx, 1, func(r mocktunnelservice.IncomingHTTPRequest) bool {
					return r.Headers.Get(harnesspkg.TestClientInstanceHeader) == client.Name() &&
						r.Headers.Get(wiretypes.ShardTokenHeader) == "placement-a"
				}))
			}
			primary := h.PrimaryClient()
			waitForToken(primary)
			require.NoError(t, primary.PausePoller(ctx))
			secondary := h.StartAdditionalClient(t)
			waitForToken(secondary)
		}),
	)
	h.ExecuteScenarious(t)
	firstTokenByClient := make(map[string]string)
	for _, request := range h.ControlPlane.ReceivedHTTPRequests() {
		name := request.Headers.Get(harnesspkg.TestClientInstanceHeader)
		if _, seen := firstTokenByClient[name]; !seen {
			firstTokenByClient[name] = request.Headers.Get(wiretypes.ShardTokenHeader)
		}
	}
	require.Len(t, firstTokenByClient, 2)
	for name, token := range firstTokenByClient {
		require.Empty(t, token, "fresh instance %s must bootstrap independently", name)
	}
}

func TestFakeRoutingCorrectionCapabilityGate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		capability []string
		oldHeader  bool
		pollToken  string
		wantStatus int
	}{
		{name: "missing", wantStatus: http.StatusOK},
		{name: "empty", capability: []string{""}, wantStatus: http.StatusOK},
		{name: "unknown", capability: []string{"wrong-cluster-v2"}, wantStatus: http.StatusOK},
		{name: "duplicate", capability: []string{clientcapabilities.WrongClusterV1, clientcapabilities.WrongClusterV1}, wantStatus: http.StatusConflict},
		{name: "supported_then_unknown", capability: []string{clientcapabilities.WrongClusterV1, "future-feature"}, wantStatus: http.StatusConflict},
		{name: "unknown_then_supported", capability: []string{"future-feature", clientcapabilities.WrongClusterV1}, wantStatus: http.StatusConflict},
		{name: "coalesced", capability: []string{"future-feature, wrong-cluster-v1, wrong-cluster-v1"}, wantStatus: http.StatusConflict},
		{name: "whitespace_and_empty_members", capability: []string{" \t, future-feature ,\twrong-cluster-v1\t,,"}, wantStatus: http.StatusConflict},
		{name: "invalid_member", capability: []string{"wrong-cluster-v1,invalid member"}, wantStatus: http.StatusOK},
		{name: "invalid_repeated_field", capability: []string{"wrong-cluster-v1", "invalid=member"}, wantStatus: http.StatusOK},
		{name: "overlong_member", capability: []string{"wrong-cluster-v1," + strings.Repeat("x", clientcapabilities.MaxTokenBytes+1)}, wantStatus: http.StatusOK},
		{name: "too_many_members", capability: []string{strings.Repeat("wrong-cluster-v1,", clientcapabilities.MaxMembers+1)}, wantStatus: http.StatusOK},
		{name: "oversized_advertisement", capability: []string{"wrong-cluster-v1", strings.Repeat(",", clientcapabilities.MaxValueBytes)}, wantStatus: http.StatusOK},
		{name: "case_mismatch", capability: []string{"Wrong-Cluster-V1"}, wantStatus: http.StatusOK},
		{name: "obsolete_one_off_header", oldHeader: true, wantStatus: http.StatusOK},
		{name: "token_without_capability", pollToken: "placement-a", wantStatus: http.StatusOK},
		{name: "supported", capability: []string{clientcapabilities.WrongClusterV1}, wantStatus: http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			service := mocktunnelservice.NewMockTunnelService(
				mocktunnelservice.WithAllowPendingCommands(),
				mocktunnelservice.WithPollHandler(func(w http.ResponseWriter, r *http.Request) bool {
					return writeFakeRoutingCorrection(w, r, "placement-a", 42)
				}),
				mocktunnelservice.WithCommandResponses(mocktunnelservice.CommandResponse{
					Command:            mocktunnelservice.NewCommand("legacy", json.RawMessage(`{"jsonrpc":"2.0","method":"notifications/ping"}`), nil),
					NoResponseExpected: true,
				}),
			)
			service.Start(t)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
				service.BaseURL().String()+"/v1/tunnels/mock-tunnel/poll", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+service.APIKey())
			req.Header.Set("Accept", "application/json")
			for _, capability := range tc.capability {
				req.Header.Add(clientcapabilities.HeaderName, capability)
			}
			if tc.oldHeader {
				req.Header.Set("X-Tunnel-Routing-Capability", clientcapabilities.WrongClusterV1)
			}
			if tc.pollToken != "" {
				req.Header.Set(wiretypes.ShardTokenHeader, tc.pollToken)
			}
			response, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer func() { _ = response.Body.Close() }()
			require.Equal(t, tc.wantStatus, response.StatusCode)
			if tc.wantStatus == http.StatusConflict {
				require.Empty(t, service.DeliveredCommands(), "correction must precede destructive queue access")
				require.Equal(t, "placement-a", response.Header.Get(wiretypes.ShardTokenHeader))
			} else {
				require.Len(t, service.DeliveredCommands(), 1, "unsupported clients retain normal delivery")
				require.Empty(t, response.Header.Get(wiretypes.ShardTokenHeader))
			}
		})
	}
}

// Capability belongs to each poll, even when supported and unsupported clients
// share a tunnel. An earlier correction must not opt later requests into it.
func TestFakeRoutingCorrectionCapabilityDoesNotLatch(t *testing.T) {
	t.Parallel()
	service := mocktunnelservice.NewMockTunnelService(
		mocktunnelservice.WithPollHandler(func(w http.ResponseWriter, r *http.Request) bool {
			return writeFakeRoutingCorrection(w, r, "placement-a", 42)
		}),
		mocktunnelservice.WithCommandResponses(
			mocktunnelservice.CommandResponse{
				Command:            mocktunnelservice.NewCommand("legacy-first", json.RawMessage(`{"jsonrpc":"2.0","method":"notifications/ping"}`), nil),
				NoResponseExpected: true,
			},
			mocktunnelservice.CommandResponse{
				Command:            mocktunnelservice.NewCommand("legacy-second", json.RawMessage(`{"jsonrpc":"2.0","method":"notifications/ping"}`), nil),
				NoResponseExpected: true,
			},
		),
	)
	service.Start(t)
	for index, capability := range []string{clientcapabilities.WrongClusterV1, "", clientcapabilities.WrongClusterV1, ""} {
		before := len(service.DeliveredCommands())
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
			service.BaseURL().String()+"/v1/tunnels/mock-tunnel/poll?limit=1", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+service.APIKey())
		req.Header.Set("Accept", "application/json")
		if capability != "" {
			req.Header.Set(clientcapabilities.HeaderName, capability)
		}
		response, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		var body struct {
			Commands []struct {
				RequestID string `json:"request_id"`
			} `json:"commands"`
		}
		err = json.NewDecoder(response.Body).Decode(&body)
		require.NoError(t, response.Body.Close())
		require.NoError(t, err)
		if capability != "" {
			require.Equal(t, http.StatusConflict, response.StatusCode)
			require.Equal(t, before, len(service.DeliveredCommands()), "correction consumed queued work")
			require.Empty(t, body.Commands)
		} else {
			require.Equal(t, http.StatusOK, response.StatusCode)
			require.Empty(t, response.Header.Get(wiretypes.ShardTokenHeader))
			require.Len(t, body.Commands, 1)
			require.Equal(t, []string{"legacy-first", "legacy-second"}[index/2], body.Commands[0].RequestID)
		}
	}
	require.Len(t, service.DeliveredCommands(), 2)
	pending, awaiting := service.PendingScriptDebugInfo()
	require.Empty(t, pending)
	require.Empty(t, awaiting)
}

// The fake service is explicitly opted in by each test. Production activation
// is independent, and even this fake cannot reject an unsupported client.
func writeFakeRoutingCorrection(w http.ResponseWriter, r *http.Request, token string, revision int) bool {
	if !clientcapabilities.Parse(r.Header.Values(clientcapabilities.HeaderName)).Supports(clientcapabilities.WrongClusterV1) {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(wiretypes.ShardTokenHeader, token)
	w.WriteHeader(http.StatusConflict)
	_, _ = fmt.Fprintf(w, `{"error":{"code":"wrong_cluster","policy_revision":%d}}`, revision)
	return true
}

func assertNoTunnelMutationRequests(t *testing.T, requests []mocktunnelservice.IncomingHTTPRequest) {
	t.Helper()
	for _, request := range requests {
		poll := request.Method == http.MethodGet && strings.HasSuffix(request.Path, "/poll")
		response := request.Method == http.MethodPost && strings.HasSuffix(request.Path, "/response")
		resource := strings.TrimPrefix(request.Path, "/v1/tunnels/")
		metadata := request.Method == http.MethodGet && resource != request.Path && resource != "" && !strings.Contains(resource, "/")
		require.True(t, poll || response || metadata, "unexpected operation: %s %s", request.Method, request.Path)
		require.Equal(t, []string{clientcapabilities.WrongClusterV1}, request.Headers.Values(clientcapabilities.HeaderName), "client capabilities apply to every control-plane request")
		require.Empty(t, request.Headers.Values("X-Tunnel-Routing-Capability"))
	}
}
