package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"testing"

	"github.com/authlete/terraform-provider-authlete/v3/internal/sdk"
	"github.com/authlete/terraform-provider-authlete/v3/internal/sdk/models/operations"
	"github.com/authlete/terraform-provider-authlete/v3/internal/sdk/models/shared"
)

// The SDK calls utils.DrainBody on a 404, which is the Delete path for both
// resources. Before the capturing transport, that left serviceIsGone and
// clientIsGone reading an empty body, so a resource genuinely deleted in the
// console made destroy -refresh=false fail.
//
// These go through the real SDK rather than building an http.Response by hand.
// The hand-built ones passed throughout, which is why this was missed.

func serverReturning(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// offline refuses any request that is not bound for the test server. Service
// Remove goes to the IdP, not to server_url, and the first version of this
// test reached the real login.authlete.com. No test may leave the machine.
type offline struct {
	allowed string
	t       *testing.T
	next    http.RoundTripper
}

func (o *offline) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != o.allowed {
		o.t.Fatalf("test tried to reach %s, which is not the test server", req.URL.Host)
	}
	return o.next.RoundTrip(req)
}

// sdkAgainst builds the SDK with the transport chain the provider uses, so the
// IdP-bound operations reach the test server as they would reach a customer's
// own identity server.
func sdkAgainst(t *testing.T, srv *httptest.Server) *sdk.Authlete {
	host := strings.TrimPrefix(srv.URL, "http://")
	chain := NewBodyCapturingTransport(srv.URL, srv.URL, 1, 1,
		NewIdpRoutingTransport(srv.URL, srv.URL, 1, 1,
			&offline{allowed: host, t: t, next: http.DefaultTransport}))
	return sdk.New(
		sdk.WithServerURL(srv.URL),
		sdk.WithClient(&http.Client{Transport: chain}),
		sdk.WithSecurity(shared.Security{Bearer: sdkPtr("test-token")}),
	)
}

func TestServiceRemoveSeesTheGoneBodyThroughTheSDK(t *testing.T) {
	srv := serverReturning(t, 404, `{"error":"Service is not found"}`)
	s := sdkAgainst(t, srv)

	apiServerID := int64(1)
	res, err := s.Service.Remove(context.Background(), shared.ServiceRemoveIdpRequest{
		APIServerID: &apiServerID,
	})
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}
	if !serviceIsGone(res.RawResponse) {
		t.Fatal("a real Authlete remove-404 must be recognised as gone through the SDK; " +
			"the SDK drains the 404 body, so this fails without the capturing transport")
	}
}

func TestClientDeleteSeesTheGoneBodyThroughTheSDK(t *testing.T) {
	srv := serverReturning(t, 404, `{"resultCode":"A001214","resultMessage":"not found"}`)
	s := sdkAgainst(t, srv)

	res, err := s.ClientManagement.ClientDeleteAPI(context.Background(), operations.ClientDeleteAPIRequest{
		ServiceID: "1",
		ClientID:  2,
	})
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}
	if !clientIsGone(res.RawResponse) {
		t.Fatal("a real Authlete client-delete-404 must be recognised as gone through the SDK")
	}
}

// The other direction, which is the reason the body is consulted at all.
func TestAForeign404IsStillNotGoneThroughTheSDK(t *testing.T) {
	srv := serverReturning(t, 404, `<html><body>nginx</body></html>`)
	s := sdkAgainst(t, srv)

	res, err := s.ClientManagement.ClientDeleteAPI(context.Background(), operations.ClientDeleteAPIRequest{
		ServiceID: "1",
		ClientID:  2,
	})
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}
	if clientIsGone(res.RawResponse) {
		t.Fatal("an nginx 404 must never count as a deletion")
	}
	if serviceIsGone(res.RawResponse) {
		t.Fatal("an nginx 404 must never count as a deletion")
	}
}

// A success must not be captured: its body can be large and the SDK reads it.
func TestASuccessIsNotCaptured(t *testing.T) {
	res := &http.Response{StatusCode: 200, Header: http.Header{}}
	if capturedBody(res) != nil {
		t.Fatal("nothing should be captured for a response the transport did not mark")
	}
}

// The capture must not reach anything that prints the response. It used to
// ride in a response header, which every diagnostic that dumps a response
// would have shown as a screenful of base64 beside the body it duplicates.
func TestTheCaptureIsNotVisibleOnTheResponse(t *testing.T) {
	srv := serverReturning(t, 404, `{"resultCode":"A001214"}`)
	s := sdkAgainst(t, srv)

	res, err := s.ClientManagement.ClientDeleteAPI(context.Background(), operations.ClientDeleteAPIRequest{
		ServiceID: "1",
		ClientID:  2,
	})
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}
	if capturedBody(res.RawResponse) == nil {
		t.Fatal("precondition: the body should have been captured")
	}
	// Headers only: by this point the SDK has drained the body, which is the
	// whole reason the capture exists, and DumpResponse refuses a body whose
	// length no longer matches Content-Length.
	dump, err := httputil.DumpResponse(res.RawResponse, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"Authlete-Provider", "Captured-Body", "Resource-Host"} {
		if strings.Contains(string(dump), s) {
			t.Errorf("a dump of the response shows %q; the capture must stay off the wire format", s)
		}
	}
}

// The host a resource lives on is server_url, even when the IdP answered.
// Recording the answering host on Create gave login.authlete.com, after which
// every genuine deletion read as a move to another host.
func TestTheResourceHostIsServerURLNotTheAnswerer(t *testing.T) {
	srv := serverReturning(t, 404, `{"error":"Service is not found"}`)
	chain := NewBodyCapturingTransport("https://api.example.test", "", 0, 0,
		&offline{allowed: strings.TrimPrefix(srv.URL, "http://"), t: t, next: http.DefaultTransport})

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/anything", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := chain.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if got := responseHost(res); got != "api.example.test" {
		t.Errorf("responseHost = %q, want the configured server_url host, not %q",
			got, res.Request.URL.Host)
	}
}

func sdkPtr(s string) *string { return &s }
