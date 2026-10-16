package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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
