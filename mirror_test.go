package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
)

func TestRoundTripFollowsBlobRedirect(t *testing.T) {
	const blob = "layer-content"

	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("storage host received Authorization header %q", got)
		}
		if got := r.Header.Get("Range"); got != "bytes=0-" {
			t.Errorf("storage host received Range header %q, want %q", got, "bytes=0-")
		}
		_, _ = io.WriteString(w, blob)
	}))
	defer storage.Close()

	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/prefix/img/blobs/sha256:abc":
			http.Redirect(w, r, storage.URL+"/blobs/sha256:abc?sig=secret", http.StatusTemporaryRedirect)
		case "/v2/prefix/img/blobs/sha256:rel":
			http.Redirect(w, r, "/artifacts-downloads/sha256:rel", http.StatusFound)
		case "/artifacts-downloads/sha256:rel":
			if r.Header.Get("Authorization") == "" {
				t.Error("registry host lost the Authorization header on a same-host redirect")
			}
			_, _ = io.WriteString(w, blob)
		default:
			http.NotFound(w, r)
		}
	}))
	defer registry.Close()

	for _, path := range []string{"/v2/prefix/img/blobs/sha256:abc", "/v2/prefix/img/blobs/sha256:rel"} {
		t.Run(path, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), ctxKeyOriginalHost, "mirror.example.com")
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, registry.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer token")
			req.Header.Set("Range", "bytes=0-")

			resp, err := (&registryRoundTripper{}).RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
			}
			if loc := resp.Header.Get("Location"); loc != "" {
				t.Errorf("response still has Location header %q", loc)
			}
			body, _ := io.ReadAll(resp.Body)
			if string(body) != blob {
				t.Errorf("body = %q, want %q", body, blob)
			}
		})
	}
}

func TestRewriteRegistryV2URL(t *testing.T) {
	rewrite := rewriteRegistryV2URL(registryConfig{registryHost: "ghcr.io", repositoryPrefix: "prefix"})

	for path, want := range map[string]string{
		"/v2/":                    "https://ghcr.io/v2/",
		"/v2/img/manifests/1.0":   "https://ghcr.io/v2/prefix/img/manifests/1.0",
		"/v2/a/b/blobs/sha256:ab": "https://ghcr.io/v2/prefix/a/b/blobs/sha256:ab",
	} {
		in := httptest.NewRequest(http.MethodGet, "http://mirror.example.com"+path, nil)
		pr := &httputil.ProxyRequest{In: in, Out: in.Clone(in.Context())}
		rewrite(pr)

		if got := pr.Out.URL.String(); got != want {
			t.Errorf("%s: url = %q, want %q", path, got, want)
		}
		if pr.Out.Host != "ghcr.io" {
			t.Errorf("%s: host = %q, want %q", path, pr.Out.Host, "ghcr.io")
		}
		if in.URL.Path != path {
			t.Errorf("%s: inbound request was modified to %q", path, in.URL.Path)
		}
	}
}

func TestTokenProxyHandler(t *testing.T) {
	var got *http.Request
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		_, _ = io.WriteString(w, `{"token":"t"}`)
	}))
	defer tokenServer.Close()

	endpoint, err := url.Parse(tokenServer.URL + "/token")
	if err != nil {
		t.Fatal(err)
	}
	handler := tokenProxyHandler(endpoint, "prefix")

	for query, wantScope := range map[string]string{
		"scope=repository:img:pull&service=ghcr.io": "repository:prefix/img:pull",
		"service=ghcr.io": "",
	} {
		got = nil
		req := httptest.NewRequest(http.MethodGet, "http://mirror.example.com/_token?"+query, nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.7")
		rec := httptest.NewRecorder()
		handler(rec, req)

		if rec.Code != http.StatusOK || got == nil {
			t.Fatalf("%s: status = %d, token server reached = %t", query, rec.Code, got != nil)
		}
		if got.URL.Path != "/token" {
			t.Errorf("%s: path = %q, want %q", query, got.URL.Path, "/token")
		}
		if s := got.URL.Query().Get("scope"); s != wantScope {
			t.Errorf("%s: scope = %q, want %q", query, s, wantScope)
		}
		if got.Host != endpoint.Host {
			t.Errorf("%s: host = %q, want %q", query, got.Host, endpoint.Host)
		}
		if xff := got.Header.Get("X-Forwarded-For"); xff != "" {
			t.Errorf("%s: token server received X-Forwarded-For %q", query, xff)
		}
	}
}
