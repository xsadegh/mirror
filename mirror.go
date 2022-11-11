package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
)

const ctxKeyOriginalHost = myContextKey("original-host")

var (
	re    = regexp.MustCompile(`^/v2/`)
	realm = regexp.MustCompile(`realm="(.*?)"`)
)

type myContextKey string

type registryConfig struct {
	registryHost     string
	repositoryPrefix string
}

func main() {
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}

	registryHost := os.Getenv("REGISTRY_HOST")
	if registryHost == "" {
		log.Fatal("REGISTRY_HOST env not specified (eg: ghcr.io)")
	}
	repositoryPrefix := os.Getenv("REPOSITORY_PREFIX")
	if repositoryPrefix == "" {
		log.Fatal("REPOSITORY_PREFIX env not specified")
	}

	reg := registryConfig{
		registryHost:     registryHost,
		repositoryPrefix: repositoryPrefix,
	}

	browserRedirects := os.Getenv("DISABLE_BROWSER_REDIRECTS") == ""
	tokenEndpoint, err := discoverTokenService(reg.registryHost)
	if err != nil {
		log.Fatalf("target registry's token endpoint could not be discovered: %+v", err)
	}
	log.Printf("discovered token endpoint for backend registry: %s", tokenEndpoint)

	var auth authenticator
	if basic := os.Getenv("AUTH_HEADER"); basic != "" {
		auth = authHeader(basic)
	}

	mux := http.NewServeMux()
	mux.Handle("/healthz", health())
	mux.Handle("/v2/", registryAPIProxy(reg, auth))
	if browserRedirects {
		mux.Handle("/", browserRedirectHandler(reg))
	}
	if tokenEndpoint != "" {
		mux.Handle("/_token", tokenProxyHandler(tokenEndpoint, repositoryPrefix))
	}

	handler := captureHostHeader(mux)
	log.Printf("starting to listen on %s", addr)
	if cert, key := os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY"); cert != "" && key != "" {
		err = http.ListenAndServeTLS(addr, cert, key, handler)
	} else {
		err = http.ListenAndServe(addr, handler)
	}
	if err != http.ErrServerClosed {
		log.Fatalf("listen error: %+v", err)
	}

	log.Printf("server shutdown successfully")
}

func health() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}
}

func discoverTokenService(registryHost string) (string, error) {
	hostURL := fmt.Sprintf("https://%s/v2/", registryHost)
	resp, err := http.Get(hostURL)
	if err != nil {
		return "", fmt.Errorf("failed to query the registry host %s: %+v", registryHost, err)
	}
	hdr := resp.Header.Get("www-authenticate")
	if hdr == "" {
		return "", fmt.Errorf("www-authenticate header not returned from %s, cannot locate token endpoint", hostURL)
	}
	matches := realm.FindStringSubmatch(hdr)
	if len(matches) == 0 {
		return "", fmt.Errorf("cannot locate 'realm' in %s response header www-authenticate: %s", hostURL, hdr)
	}
	return matches[1], nil
}

// captureHostHeader is a middleware to capture Host header in a context key.
func captureHostHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		ctx := context.WithValue(req.Context(), ctxKeyOriginalHost, req.Host)
		req = req.WithContext(ctx)
		next.ServeHTTP(rw, req.WithContext(ctx))
	})
}

// tokenProxyHandler proxies the token requests to the specified token service.
// It adjusts the ?scope= parameter in the query from "repository:foo:..." to
// "repository:repoPrefix/foo:.." and reverse proxies the query to the specified
// tokenEndpoint.
func tokenProxyHandler(tokenEndpoint, repoPrefix string) http.HandlerFunc {
	return (&httputil.ReverseProxy{
		FlushInterval: -1,
		Director: func(r *http.Request) {
			orig := r.URL.String()

			q := r.URL.Query()
			scope := q.Get("scope")
			if scope == "" {
				return
			}
			newScope := strings.Replace(scope, "repository:", fmt.Sprintf("repository:%s/", repoPrefix), 1)
			q.Set("scope", newScope)
			u, _ := url.Parse(tokenEndpoint)
			u.RawQuery = q.Encode()
			r.URL = u
			log.Printf("tokenProxyHandler: rewrote url:%s into:%s", orig, r.URL)
			r.Host = u.Host
		},
	}).ServeHTTP
}

// browserRedirectHandler redirects a request like example.com/my-image to
// REGISTRY_HOST/my-image, which shows a public UI for browsing the registry.
// This works only on registries that support a web UI when the image name is
// entered into the browser, like GCR (gcr.io/google-containers/busybox).
func browserRedirectHandler(cfg registryConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hostURL := fmt.Sprintf("https://%s/%s%s", cfg.registryHost, cfg.repositoryPrefix, r.RequestURI)
		http.Redirect(w, r, hostURL, http.StatusTemporaryRedirect)
	}
}

// registryAPIProxy returns a reverse proxy to the specified registry.
func registryAPIProxy(cfg registryConfig, auth authenticator) http.HandlerFunc {
	return (&httputil.ReverseProxy{
		FlushInterval: -1,
		Director:      rewriteRegistryV2URL(cfg),
		Transport: &registryRoundTripper{
			auth: auth,
		},
	}).ServeHTTP
}

// rewriteRegistryV2URL rewrites request.URL like /v2/* that come into the server
// into https://[GCR_HOST]/v2/[PROJECT_ID]/*. It leaves /v2/ as is.
func rewriteRegistryV2URL(c registryConfig) func(*http.Request) {
	return func(req *http.Request) {
		u := req.URL.String()
		req.Host = c.registryHost
		req.URL.Scheme = "https"
		req.URL.Host = c.registryHost
		if req.URL.Path != "/v2/" {
			req.URL.Path = re.ReplaceAllString(req.URL.Path, fmt.Sprintf("/v2/%s/", c.repositoryPrefix))
		}
		log.Printf("rewrote url: %s into %s", u, req.URL)
	}
}

type registryRoundTripper struct {
	auth authenticator
}

func (rrt *registryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	log.Printf("request received. url=%s", req.URL)

	if rrt.auth != nil {
		req.Header.Set("Authorization", rrt.auth.AuthHeader())
	}

	origHost := req.Context().Value(ctxKeyOriginalHost).(string)
	if ua := req.Header.Get("user-agent"); ua != "" {
		req.Header.Set("user-agent", "gcr-proxy/0.1 customDomain/"+origHost+" "+ua)
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err == nil {
		log.Printf("request completed (status=%d) url=%s", resp.StatusCode, req.URL)
	} else {
		log.Printf("request failed with error: %+v", err)
		return nil, err
	}

	// Google Artifact Registry sends a "location: /artifacts-downloads/..." URL
	// to download blobs. We don't want these routed to the proxy itself.
	if locHdr := resp.Header.Get("location"); req.Method == http.MethodGet &&
		resp.StatusCode == http.StatusFound && strings.HasPrefix(locHdr, "/") {
		resp.Header.Set("location", req.URL.Scheme+"://"+req.URL.Host+locHdr)
	}

	updateTokenEndpoint(resp, origHost)
	return resp, nil
}

// updateTokenEndpoint modifies the response header like:
//
//	Www-Authenticate: Bearer realm="https://auth.docker.io/token",service="registry.docker.io"
//
// to point to the https://host/token endpoint to force using local token
// endpoint proxy.
func updateTokenEndpoint(resp *http.Response, host string) {
	v := resp.Header.Get("www-authenticate")
	if v == "" {
		return
	}
	cur := fmt.Sprintf("https://%s/_token", host)
	resp.Header.Set("www-authenticate", realm.ReplaceAllString(v, fmt.Sprintf(`realm="%s"`, cur)))
}

type authenticator interface {
	AuthHeader() string
}

type authHeader string

func (b authHeader) AuthHeader() string { return string(b) }
