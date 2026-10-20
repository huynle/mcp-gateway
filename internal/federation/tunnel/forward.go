package tunnel

import (
	"io"
	"net/http"
	"net/url"
)

// httpForwarder forwards tunnel requests to one private HTTP MCP server.
// Requests always go to the target's scheme and host, whatever path the
// gateway sends: the gateway can never make the tunnel client reach any
// other host. The root path "/" maps to the target URL's own path and
// query, other paths (e.g. a legacy SSE server's /messages endpoint) are
// kept as they are.
type httpForwarder struct {
	target *url.URL
	hc     *http.Client
}

// NewHTTPForwarder returns the client-side handler that replays tunnel
// requests against the private HTTP MCP server at target through hc (the
// caller's client: no proxies, redirects passed through). The legacy
// tunnel client (--http) and the machine agent serve it.
func NewHTTPForwarder(target *url.URL, hc *http.Client) http.Handler {
	return &httpForwarder{target: target, hc: hc}
}

func (f *httpForwarder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	out := &url.URL{Scheme: f.target.Scheme, Host: f.target.Host}
	if r.URL.Path == "" || r.URL.Path == "/" {
		out.Path, out.RawPath, out.RawQuery = f.target.Path, f.target.RawPath, f.target.RawQuery
		if r.URL.RawQuery != "" {
			if out.RawQuery != "" {
				out.RawQuery += "&"
			}
			out.RawQuery += r.URL.RawQuery
		}
	} else {
		out.Path, out.RawPath, out.RawQuery = r.URL.Path, r.URL.RawPath, r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, f.target.String(), r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.URL = out
	req.Host = ""
	req.ContentLength = r.ContentLength
	req.Header = cleanHeader(r.Header)

	resp, err := f.hc.Do(req)
	if err != nil {
		http.Error(w, "local MCP server unreachable", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	for k, vs := range cleanHeader(resp.Header) {
		w.Header()[k] = vs
	}
	w.WriteHeader(resp.StatusCode)
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush() // stream SSE events as they arrive
			}
		}
		if err != nil {
			if err != io.EOF {
				panic(http.ErrAbortHandler) // the tunnel reports the stream as broken
			}
			return
		}
	}
}
