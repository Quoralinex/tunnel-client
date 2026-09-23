package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/openai/tunnel-client/pkg/config"
	tctransport "github.com/openai/tunnel-client/pkg/transport"
)

func TestRootCommandIncludesRun(t *testing.T) {
	t.Parallel()

	root := newRootCommand(func(string) (string, bool) { return "", false }, io.Discard, io.Discard)

	run, _, err := root.Find([]string{"run"})
	require.NoError(t, err)
	require.Equal(t, "run", run.Name())
	require.NotNil(t, run.Flags().Lookup("control-plane.base-url"))
}

func TestRunHelpIsScoped(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	root := newRootCommand(func(string) (string, bool) { return "", false }, &stdout, io.Discard)

	root.SetArgs([]string{"run", "--help"})

	require.NoError(t, root.Execute())
	output := stdout.String()
	require.Contains(t, output, "control-plane.base-url")
	require.Contains(t, output, "embedded-mcp-stub")
	require.Contains(t, output, "embedded-stateless-mcp-stub")
	require.NotContains(t, output, "Commands:")
}

func TestRunCommandAddsOnlyEmbeddedStubFlagsToFullConfigSurface(t *testing.T) {
	t.Parallel()

	run := newRunCommand(func(string) (string, bool) { return "", false })
	fullConfigFlags := pflag.NewFlagSet("full-config", pflag.ContinueOnError)
	config.RegisterFlags(fullConfigFlags)

	got := runCommandFlagNames(run.Flags())
	want := append(runCommandFlagNames(fullConfigFlags),
		"embedded-mcp-listen-addr",
		"embedded-mcp-server-name",
		"embedded-mcp-server-version",
		"embedded-mcp-stub",
		"embedded-mcp-unix-socket",
		"embedded-stateless-mcp-stub",
	)
	sort.Strings(want)
	require.Equal(t, want, got)
	require.Equal(t, "false", run.Flags().Lookup("embedded-mcp-stub").DefValue)
	require.Equal(t, "false", run.Flags().Lookup("embedded-stateless-mcp-stub").DefValue)
	require.Equal(t, defaultDevMCPStubListenAddr, run.Flags().Lookup("embedded-mcp-listen-addr").DefValue)
	require.Equal(t, "", run.Flags().Lookup("embedded-mcp-unix-socket").DefValue)
	require.Equal(t, defaultDevMCPStubName, run.Flags().Lookup("embedded-mcp-server-name").DefValue)
	require.Equal(t, defaultDevMCPStubVersion, run.Flags().Lookup("embedded-mcp-server-version").DefValue)
}

func TestRunReportsTunnelIDBeforeMissingMCPBinding(t *testing.T) {
	t.Parallel()

	root := newRootCommand(func(key string) (string, bool) {
		switch key {
		case "LOG_FORMAT":
			return "struct-text", true
		case "OPENAI_API_KEY":
			return "dummy-key", true
		default:
			return "", false
		}
	}, io.Discard, io.Discard)

	root.SetArgs([]string{"run"})

	err := root.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "tunnel ID is required")
	require.Contains(t, err.Error(), "tunnel-client admin tunnels create --help")
	require.Contains(t, err.Error(), "tunnel-client init")
	require.Contains(t, err.Error(), "tunnel-client help quickstart")
}

func TestRunReportsHowToConfigureMainMCPChannel(t *testing.T) {
	t.Parallel()

	root := newRootCommand(func(key string) (string, bool) {
		switch key {
		case "LOG_FORMAT":
			return "struct-text", true
		case "OPENAI_API_KEY":
			return "dummy-key", true
		case "CONTROL_PLANE_TUNNEL_ID":
			return "tunnel_0123456789abcdef0123456789abcdef", true
		default:
			return "", false
		}
	}, io.Discard, io.Discard)

	root.SetArgs([]string{"run"})

	err := root.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "set --mcp.server-url or --mcp.command")
	require.Contains(t, err.Error(), "tunnel-client run --embedded-mcp-stub")
	require.Contains(t, err.Error(), "--health.listen-addr 127.0.0.1:0")
	require.Contains(t, err.Error(), "--health.url-file /tmp/tunnel-client-health.url")
	require.Contains(t, err.Error(), "tunnel-client init")
}

func TestRunEmbeddedMCPStubConfiguresMainChannel(t *testing.T) {
	t.Parallel()

	for _, mode := range []struct {
		name      string
		stateless bool
		unix      bool
	}{
		{name: "Compatible"},
		{name: "Stateless", stateless: true},
		{name: "CompatibleUnix", unix: true},
		{name: "StatelessUnix", stateless: true, unix: true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			run := newRunCommand(func(string) (string, bool) { return "", false })
			run.SetOut(&out)
			opts := runEmbeddedMCPStubOptions{
				Enabled:       !mode.stateless,
				Stateless:     mode.stateless,
				ListenAddr:    "127.0.0.1:0",
				ServerName:    "custom-stub",
				ServerVersion: "1.2.3",
			}
			if mode.unix {
				if runtime.GOOS == "windows" {
					t.Skip("Unix socket listener")
				}
				opts.UnixSocket = shortSocketPath(t, "embedded-mcp-*.sock")
			}
			stub, err := configureRunEmbeddedMCPStub(run, opts)
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, stub.Shutdown(context.TODO()))
				if mode.unix {
					require.NoFileExists(t, opts.UnixSocket)
				}
			})

			cfg, err := loadRunConfig(run, func(key string) (string, bool) {
				switch key {
				case "OPENAI_API_KEY":
					return "dummy-key", true
				case "CONTROL_PLANE_TUNNEL_ID":
					return "tunnel_0123456789abcdef0123456789abcdef", true
				case "MCP_SERVER_URL":
					return "http://127.0.0.1:1/ignored-environment-target", true
				default:
					return "", false
				}
			}, opts, stub)
			require.NoError(t, err)
			binding := cfg.MCP.MainChannelBinding()
			require.NotNil(t, binding)
			require.NotNil(t, binding.ServerURL)
			require.Equal(t, stub.MCPURL(), binding.ServerURL.String())
			require.Equal(t, mode.stateless, binding.Stateless)
			require.Equal(t, opts.UnixSocket, stub.UnixSocket)
			require.Equal(t, opts.UnixSocket, binding.UnixSocketPath)
			require.Equal(t, opts.UnixSocket, cfg.MCP.UnixSocketPath)
			if mode.unix {
				require.Equal(t, "unix", stub.listener.Addr().Network())
				require.Equal(t, "localhost", stub.BaseURL.Hostname())
				require.Empty(t, stub.BaseURL.Port())
				require.Nil(t, binding.HTTPProxy)
				require.Contains(t, out.String(), "MCP Unix socket: "+opts.UnixSocket)
			} else {
				require.Equal(t, "tcp", stub.listener.Addr().Network())
				require.Equal(t, "127.0.0.1", stub.BaseURL.Hostname())
				require.NotEqual(t, "0", stub.BaseURL.Port())
			}
			require.Contains(t, out.String(), "These are the embedded demo MCP/OAuth endpoints")
			transport, err := tctransport.ApplyUnixSocketPath(http.DefaultTransport.(*http.Transport).Clone(), binding.UnixSocketPath)
			require.NoError(t, err)
			httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			t.Cleanup(httpClient.CloseIdleConnections)

			resp, err := httpClient.Get(stub.ProtectedResourceMetadataURL())
			require.NoError(t, err)
			t.Cleanup(func() { _ = resp.Body.Close() })
			require.Equal(t, http.StatusOK, resp.StatusCode)

			info := readDevMCPStubResult(t, postDevMCPStubRequestWithClient(t, httpClient, stub.MCPURL(), "2026-07-28", "", "tools/call", map[string]any{
				"name": "server_info", "arguments": map[string]any{},
			}))
			require.Equal(t, []any{map[string]any{
				"type": "text", "text": "custom-stub 1.2.3 demo tools: server_info, echo, uppercase",
			}}, info["content"])
		})
	}
}

func TestRunEmbeddedMCPStubRejectsConflictingListeners(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"embedded-mcp-stub", "embedded-stateless-mcp-stub"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			run := newRunCommand(func(string) (string, bool) { return "", false })
			run.SetOut(io.Discard)
			run.SetErr(io.Discard)
			run.SetArgs([]string{"--" + mode, "--embedded-mcp-listen-addr=127.0.0.1:0", "--embedded-mcp-unix-socket=/tmp/unused-mcp.sock"})
			require.EqualError(t, run.Execute(), "--embedded-mcp-listen-addr and --embedded-mcp-unix-socket are mutually exclusive")
		})
	}
}

func TestRunEmbeddedMCPStubClosesUnixSocketAfterConfigFailure(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket listener")
	}
	for _, mode := range []string{"embedded-mcp-stub", "embedded-stateless-mcp-stub"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			socketPath := shortSocketPath(t, "embedded-mcp-failure-*.sock")
			run := newRunCommand(func(string) (string, bool) { return "", false })
			run.SetOut(io.Discard)
			run.SetErr(io.Discard)
			run.SetArgs([]string{"--" + mode, "--embedded-mcp-unix-socket=" + socketPath})
			require.ErrorContains(t, run.Execute(), "tunnel ID is required")
			require.NoFileExists(t, socketPath)
		})
	}
}

func TestRunEmbeddedMCPStubPreservesExistingUnixSocketPath(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket listener")
	}
	socketPath := shortSocketPath(t, "embedded-mcp-existing-*.sock")
	require.NoError(t, os.WriteFile(socketPath, []byte("owned by another process"), 0o600))
	_, err := startDevMCPStub(devMCPStubOptions{UnixSocket: socketPath})
	require.Error(t, err)
	contents, err := os.ReadFile(socketPath)
	require.NoError(t, err)
	require.Equal(t, "owned by another process", string(contents))
}

func TestRunEmbeddedMCPStubRejectsExplicitMainMCPFlags(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{"embedded-mcp-stub", "embedded-stateless-mcp-stub"} {
		for _, target := range []struct {
			flag  string
			value string
		}{
			{flag: "mcp.command", value: "command=python,channel=main"},
			{flag: "mcp-command", value: "command=python,channel=main"},
			{flag: "mcp.server-url", value: "url=http://127.0.0.1:1/mcp,channel=main"},
			{flag: "mcp-server-url", value: "url=http://127.0.0.1:1/mcp,channel=main"},
		} {
			t.Run(mode+"/"+target.flag, func(t *testing.T) {
				t.Parallel()
				var out bytes.Buffer
				run := newRunCommand(func(string) (string, bool) { return "", false })
				run.SetOut(&out)
				run.SetErr(io.Discard)
				run.SetArgs([]string{"--" + mode, "--" + target.flag, target.value})
				err := run.Execute()
				require.EqualError(t, err, "--"+mode+" cannot be combined with --"+target.flag+"; use one main MCP target path")
				require.NotContains(t, out.String(), "Embedded MCP stub enabled")
			})
		}
	}
}

func TestRunEmbeddedStatelessMCPStubOverridesInheritedMain(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		source       string
		explicitMain bool
	}{
		{name: "NoTarget"},
		{name: "EnvironmentImplicitMain", source: "environment"},
		{name: "EnvironmentExplicitMain", source: "environment", explicitMain: true},
		{name: "YAMLImplicitMain", source: "config"},
		{name: "YAMLExplicitMain", source: "config", explicitMain: true},
		{name: "ProfileImplicitMain", source: "profile"},
		{name: "ProfileExplicitMain", source: "profile", explicitMain: true},
		{name: "EnvironmentOverridesProfile", source: "profile-env", explicitMain: true},
		{name: "EnvironmentHTTPMain", source: "http"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := map[string]string{}
			run := newRunCommand(embeddedStubConfigTestEnv(env))
			run.SetOut(io.Discard)
			wantChannels := []string{"main"}
			if tc.source == "config" || strings.HasPrefix(tc.source, "profile") {
				mainChannel := ""
				if tc.explicitMain {
					mainChannel = "      channel: main\n"
				}
				profileDir := t.TempDir()
				profilePath := filepath.Join(profileDir, "embedded-targets.yaml")
				require.NoError(t, os.WriteFile(profilePath, []byte("mcp:\n"+
					"  server_urls:\n    - channel: file-http\n      url: https://file.example/mcp\n"+
					"  commands:\n    - command: python original.py\n"+mainChannel+
					"    - channel: file-tools\n      command: python file-tools.py\n"), 0o600))
				if tc.source == "config" {
					require.NoError(t, run.Flags().Set("config", profilePath))
				} else {
					require.NoError(t, run.Flags().Set("profile", "embedded-targets"))
					require.NoError(t, run.Flags().Set("profile-dir", profileDir))
				}
				wantChannels = []string{"file-http", "file-tools", "main"}
			}
			if tc.source == "environment" || tc.source == "profile-env" || tc.source == "http" {
				mainCommand := "python original.py"
				if tc.explicitMain {
					mainCommand = "channel=main,command=" + mainCommand
				}
				env["MCP_COMMAND"] = mainCommand + "\nchannel=env-tools,command=python env-tools.py"
				env["MCP_SERVER_URL"] = "channel=env-http,url=https://env.example/mcp"
				if tc.source == "http" {
					env["MCP_COMMAND"] = "channel=env-tools,command=python env-tools.py"
					env["MCP_SERVER_URL"] += "\nchannel=main,url=https://original.example/mcp"
				}
				wantChannels = []string{"env-http", "env-tools", "main"}
			}
			opts := runEmbeddedMCPStubOptions{Stateless: true, ListenAddr: "127.0.0.1:0"}
			stub, err := configureRunEmbeddedMCPStub(run, opts)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, stub.Shutdown(context.TODO())) })
			require.False(t, run.Flags().Lookup("mcp.server-url").Changed)

			lookupEnv := embeddedStubConfigTestEnv(env)
			original, originalErr := config.LoadFromFlagSet(run.Flags(), lookupEnv)
			cfg, err := loadRunConfig(run, lookupEnv, opts, stub)
			require.NoError(t, err)
			main := cfg.MCP.MainChannelBinding()
			require.NotNil(t, main)
			require.Equal(t, stub.MCPURL(), main.ServerURL.String())
			require.Equal(t, config.MCPTransportHTTPStreamable, main.TransportKind)
			require.Equal(t, main.ServerURL, cfg.MCP.ServerURL)
			require.Equal(t, main.TransportKind, cfg.MCP.TransportKind)
			require.Empty(t, cfg.MCP.Command)
			require.Empty(t, cfg.MCP.CommandArgs)
			var channels []string
			for _, binding := range cfg.MCP.ChannelBindings {
				channels = append(channels, binding.Channel.String())
			}
			require.ElementsMatch(t, wantChannels, channels)
			if tc.source == "" {
				require.ErrorContains(t, originalErr, "main channel is required")
			} else {
				require.NoError(t, originalErr)
				for _, binding := range original.MCP.ChannelBindings {
					if binding.Channel.String() != "main" {
						require.Equal(t, &binding, cfg.MCP.ChannelBindingFor(binding.Channel))
					}
				}
				require.Equal(t, original.Runtime, cfg.Runtime)
			}
		})
	}
}

func TestRunEmbeddedStatelessMCPStubDoesNotInheritConfiguredProxy(t *testing.T) {
	t.Parallel()

	for _, proxyEnv := range []string{"MCP_HTTP_PROXY", "TUNNEL_CLIENT_HTTP_PROXY"} {
		t.Run(proxyEnv, func(t *testing.T) {
			t.Parallel()
			var proxyRequests atomic.Int32
			poisonProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				proxyRequests.Add(1)
				http.Error(w, "configured proxy must not receive embedded main requests", http.StatusBadGateway)
			}))
			t.Cleanup(poisonProxy.Close)
			env := map[string]string{proxyEnv: poisonProxy.URL}
			lookupEnv := embeddedStubConfigTestEnv(env)
			run := newRunCommand(lookupEnv)
			run.SetOut(io.Discard)
			opts := runEmbeddedMCPStubOptions{Stateless: true, ListenAddr: "127.0.0.1:0"}
			stub, err := configureRunEmbeddedMCPStub(run, opts)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, stub.Shutdown(context.TODO())) })
			env["MCP_SERVER_URL"] = "channel=other,url=" + stub.MCPURL()
			cfg, err := loadRunConfig(run, lookupEnv, opts, stub)
			require.NoError(t, err)
			main := cfg.MCP.MainChannelBinding()
			require.NotNil(t, main)
			require.Nil(t, main.HTTPProxy)
			require.Equal(t, config.ProxySourceNone, main.HTTPProxySource)
			require.Equal(t, poisonProxy.URL, cfg.MCP.HTTPProxy.String(), "shared proxy defaults must remain configured")

			request := func(binding config.MCPChannelBinding) *http.Response {
				t.Helper()
				transport, err := tctransport.ApplyProxy(tctransport.CloneDefault(), binding.HTTPProxy)
				require.NoError(t, err)
				client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
				t.Cleanup(client.CloseIdleConnections)
				return postDevMCPStubRequestWithClient(t, client, binding.ServerURL.String(), "2026-07-28", "", "tools/call", map[string]any{
					"name": "echo", "arguments": map[string]any{"input": "direct embedded request"},
				})
			}
			response := request(*main)
			require.Empty(t, response.Header.Get("Mcp-Session-Id"))
			result := readDevMCPStubResult(t, response)
			require.Equal(t, []any{map[string]any{"type": "text", "text": "direct embedded request"}}, result["content"])
			require.Zero(t, proxyRequests.Load())

			for _, binding := range cfg.MCP.ChannelBindings {
				if binding.Channel.String() != "other" {
					continue
				}
				require.Equal(t, poisonProxy.URL, binding.HTTPProxy.String())
				require.Equal(t, config.ProxySource(proxyEnv), binding.HTTPProxySource)
				response := request(binding)
				require.Equal(t, http.StatusBadGateway, response.StatusCode)
				require.NoError(t, response.Body.Close())
			}
			require.EqualValues(t, 1, proxyRequests.Load(), "other channel must still use the configured proxy")

			legacyRun := newRunCommand(lookupEnv)
			legacyRun.SetOut(io.Discard)
			legacyOpts := runEmbeddedMCPStubOptions{Enabled: true, ListenAddr: "127.0.0.1:0"}
			legacyStub, err := configureRunEmbeddedMCPStub(legacyRun, legacyOpts)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, legacyStub.Shutdown(context.TODO())) })
			legacyCfg, err := loadRunConfig(legacyRun, lookupEnv, legacyOpts, legacyStub)
			require.NoError(t, err)
			legacyMain := legacyCfg.MCP.MainChannelBinding()
			require.Equal(t, poisonProxy.URL, legacyMain.HTTPProxy.String())
			response = request(*legacyMain)
			require.Equal(t, http.StatusBadGateway, response.StatusCode)
			require.NoError(t, response.Body.Close())
			require.EqualValues(t, 2, proxyRequests.Load(), "legacy embedded mode must retain proxy behavior")
		})
	}
}

func TestRunEmbeddedStatelessMCPStubPreservesConfiguredTargetValidation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		env  map[string]string
	}{
		{name: "DuplicateMainTransports", env: map[string]string{"MCP_COMMAND": "echo main", "MCP_SERVER_URL": "https://main.example/mcp"}},
		{name: "DuplicateMainHTTP", env: map[string]string{"MCP_SERVER_URL": "https://one.example/mcp\nchannel=main,url=https://two.example/mcp"}},
		{name: "DuplicateMainStdio", env: map[string]string{"MCP_COMMAND": "echo one\nchannel=main,command=echo two"}},
		{name: "DuplicateOtherChannel", env: map[string]string{"MCP_COMMAND": "echo main\nchannel=tools,command=echo tools", "MCP_SERVER_URL": "channel=tools,url=https://tools.example/mcp"}},
		{name: "InvalidMainCommand", env: map[string]string{"MCP_COMMAND": `echo "unterminated`}},
		{name: "InvalidMainURL", env: map[string]string{"MCP_SERVER_URL": "://invalid"}},
		{name: "MainSocketAndProxy", env: map[string]string{"MCP_SERVER_URL": "channel=main,url=http://localhost/mcp,unix-socket=/tmp/embedded-main.sock,http-proxy=http://proxy.example:8080"}},
		{name: "OtherSocketAndProxy", env: map[string]string{"MCP_COMMAND": "echo main", "MCP_SERVER_URL": "channel=tools,url=http://localhost/mcp,unix-socket=/tmp/embedded-tools.sock,http-proxy=http://proxy.example:8080"}},
		{name: "InvalidCommonSetting", env: map[string]string{"MCP_COMMAND": "echo main", "MCP_CONNECTION_MAX_TTL": "-1s"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lookupEnv := embeddedStubConfigTestEnv(tc.env)
			run := newRunCommand(lookupEnv)
			_, originalErr := config.LoadFromFlagSet(run.Flags(), lookupEnv)
			require.Error(t, originalErr)
			stub := &devMCPStubInstance{BaseURL: &url.URL{Scheme: "http", Host: "127.0.0.1:12345"}}
			_, err := loadRunConfig(run, lookupEnv, runEmbeddedMCPStubOptions{Stateless: true}, stub)
			require.EqualError(t, err, originalErr.Error())
		})
	}
}

func TestRunEmbeddedMCPStubPreservesInheritedCommandConflict(t *testing.T) {
	t.Parallel()

	for _, source := range []string{"environment", "config", "profile"} {
		t.Run(source, func(t *testing.T) {
			t.Parallel()
			env := map[string]string{}
			run := newRunCommand(embeddedStubConfigTestEnv(env))
			run.SetOut(io.Discard)
			if source == "environment" {
				env["MCP_COMMAND"] = "echo original"
			} else {
				dir := t.TempDir()
				path := filepath.Join(dir, "original.yaml")
				require.NoError(t, os.WriteFile(path, []byte("mcp:\n  commands:\n    - channel: main\n      command: echo original\n"), 0o600))
				if source == "config" {
					require.NoError(t, run.Flags().Set("config", path))
				} else {
					require.NoError(t, run.Flags().Set("profile", "original"))
					require.NoError(t, run.Flags().Set("profile-dir", dir))
				}
			}
			opts := runEmbeddedMCPStubOptions{Enabled: true, ListenAddr: "127.0.0.1:0"}
			stub, err := configureRunEmbeddedMCPStub(run, opts)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, stub.Shutdown(context.TODO())) })
			_, err = loadRunConfig(run, embeddedStubConfigTestEnv(env), opts, stub)
			require.EqualError(t, err, `mcp config: duplicate channel "main" from mcp.command (http-streamable already configured)`)
		})
	}
}

func embeddedStubConfigTestEnv(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		if value, ok := values[key]; ok {
			return value, true
		}
		switch key {
		case "OPENAI_API_KEY":
			return "dummy-key", true
		case "CONTROL_PLANE_TUNNEL_ID":
			return "tunnel_0123456789abcdef0123456789abcdef", true
		default:
			return "", false
		}
	}
}

func TestRunEmbeddedMCPStubModesAreMutuallyExclusive(t *testing.T) {
	t.Parallel()

	run := newRunCommand(func(string) (string, bool) { return "", false })
	run.SetOut(io.Discard)
	run.SetErr(io.Discard)
	run.SetArgs([]string{"--embedded-mcp-stub", "--embedded-stateless-mcp-stub"})
	require.EqualError(t, run.Execute(), "--embedded-mcp-stub and --embedded-stateless-mcp-stub are mutually exclusive")
}

func TestRunEmbeddedMCPStubExplicitFalseDoesNotEnableMode(t *testing.T) {
	t.Parallel()

	for _, disabled := range []string{"embedded-mcp-stub", "embedded-stateless-mcp-stub"} {
		t.Run(disabled, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			run := newRunCommand(func(string) (string, bool) { return "", false })
			run.SetOut(&out)
			run.SetErr(io.Discard)
			run.SetArgs([]string{"--" + disabled + "=false", "--embedded-mcp-listen-addr", "invalid-listen-address"})
			require.ErrorContains(t, run.Execute(), "tunnel ID is required")
			require.NotContains(t, out.String(), "Embedded MCP stub enabled")
		})
	}
}

func TestRunEmbeddedMCPStubStartupValidationAndShutdown(t *testing.T) {
	t.Parallel()

	for _, mode := range []struct {
		enabled  string
		disabled string
	}{
		{enabled: "embedded-mcp-stub", disabled: "embedded-stateless-mcp-stub"},
		{enabled: "embedded-stateless-mcp-stub", disabled: "embedded-mcp-stub"},
	} {
		for _, listenAddr := range []string{"invalid-listen-address", "127.0.0.1:0"} {
			t.Run(mode.enabled+"/"+listenAddr, func(t *testing.T) {
				t.Parallel()
				var out bytes.Buffer
				run := newRunCommand(func(string) (string, bool) { return "", false })
				run.SetOut(&out)
				run.SetErr(io.Discard)
				run.SetArgs([]string{"--" + mode.enabled, "--" + mode.disabled + "=false", "--embedded-mcp-listen-addr", listenAddr})
				err := run.Execute()
				if listenAddr == "invalid-listen-address" {
					require.ErrorContains(t, err, "start embedded MCP stub:")
					return
				}
				require.ErrorContains(t, err, "tunnel ID is required")
				_, endpointOutput, found := strings.Cut(out.String(), "  MCP URL: ")
				require.True(t, found)
				endpoint, _, _ := strings.Cut(endpointOutput, "\n")
				resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(endpoint)
				if resp != nil {
					_ = resp.Body.Close()
				}
				require.Error(t, err, "the embedded listener must close when configuration validation fails")
			})
		}
	}
}

func runCommandFlagNames(fs *pflag.FlagSet) []string {
	names := make([]string, 0)
	fs.VisitAll(func(flag *pflag.Flag) {
		names = append(names, flag.Name)
	})
	sort.Strings(names)
	return names
}
