package internal

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/openai/tunnel-client/pkg/controlplane/apierror"
	"github.com/openai/tunnel-client/pkg/controlplane/wiretypes"
)

const maxRoutingFailures = 3

// pollingTransportError keeps network classification and cancellation available
// to callers without logging a URL or a tunnel-specific gateway hostname.
type pollingTransportError struct{ cause error }

func (e *pollingTransportError) Error() string {
	category, _ := healthFailure(e.cause)
	return "controlplane client: poll transport failed (" + category + ")"
}

func (e *pollingTransportError) Unwrap() error { return e.cause }

// pollRoutingState belongs to one immutable tunnel/endpoint client. A generation
// fences all completed state-bearing results, including successful empty polls.
// Keep the revision watermark through tokenless recovery to prevent rollback.
type pollRoutingState struct {
	mu            sync.Mutex
	generation    uint64
	token         string
	revision      uint64
	known         bool
	acceptedToken string
	failures      int
	corrections   int
}

type routingAttempt struct {
	generation uint64
	token      string
}

func (s *pollRoutingState) snapshot() routingAttempt {
	s.mu.Lock()
	defer s.mu.Unlock()
	return routingAttempt{generation: s.generation, token: s.token}
}

func (s *pollRoutingState) complete(attempt routingAttempt, correction *wiretypes.RoutingCorrection, available, failedDestination bool) {
	if correction == nil && !available && !failedDestination {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if attempt.generation != s.generation {
		return
	}
	s.generation++
	switch {
	case available:
		s.failures, s.corrections = 0, 0
	case correction != nil:
		s.failures = 0
		s.corrections++
		switch {
		case !s.known || correction.PolicyRevision > s.revision:
			s.known = true
			s.revision = correction.PolicyRevision
			s.acceptedToken = correction.ShardToken
			s.token = correction.ShardToken
		case correction.PolicyRevision == s.revision:
			if correction.ShardToken == s.acceptedToken {
				s.token = correction.ShardToken
			} else {
				// Never choose between rival tokens for one revision.
				s.token = ""
			}
		}
		if s.corrections >= maxRoutingFailures {
			s.token, s.corrections = "", 0
		}
	case failedDestination && attempt.token != "":
		s.failures++
		if s.failures >= maxRoutingFailures {
			s.token, s.failures = "", 0
		}
	}
}

// pollStatusError keeps correction bodies bounded and private, including invalid
// corrections. Closing the body instead of draining unbounded data preserves
// the poll deadline and never prints replacement tokens in error diagnostics.
func (c *TunnelServiceClient) pollStatusError(resp *http.Response) (*APIStatusError, *wiretypes.RoutingCorrection, bool) {
	statusErr := &APIStatusError{
		prefix: "controlplane client: unexpected status", statusCode: resp.StatusCode,
		status: fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode)),
	}
	statusErr.retryAfter, statusErr.hasRetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), c.nowTime())
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxControlPlaneErrorBodySize+1))
	if err != nil {
		statusErr.info.Message = "invalid polling error response"
		// Losing a response body is a destination failure regardless of the
		// received status. Retain only its classification, never network details.
		var networkErr net.Error
		failedBody := errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &networkErr)
		return statusErr, nil, failedBody
	}
	if len(body) > maxControlPlaneErrorBodySize {
		statusErr.info.Message = "invalid polling error response"
		return statusErr, nil, false
	}
	populateAPIStatusError(statusErr, body)
	if resp.StatusCode != http.StatusConflict {
		if statusErr.Code() == wiretypes.WrongClusterCode || len(resp.Header.Values(wiretypes.ShardTokenHeader)) != 0 {
			statusErr.info = apierror.Info{Message: "invalid polling routing correction"}
		}
		return statusErr, nil, false
	}
	correction, parseErr := wiretypes.ParseRoutingCorrection(resp.Header, body)
	if statusErr.Code() == wiretypes.WrongClusterCode || len(resp.Header.Values(wiretypes.ShardTokenHeader)) != 0 || parseErr != nil {
		statusErr.info = apierror.Info{Message: "invalid polling routing correction"}
		if correction != nil {
			statusErr.info = apierror.Info{Code: wiretypes.WrongClusterCode, Message: "polling placement rejected; retrying after backoff"}
		}
	}
	return statusErr, correction, false
}
