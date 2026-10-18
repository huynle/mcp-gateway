package tunnelclient

import (
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
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

func newHTTPForwarder(target *url.URL, hc *http.Client) http.Handler {
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
	copyHeader(req.Header, r.Header)

	resp, err := f.hc.Do(req)
	if err != nil {
		http.Error(w, "local MCP server unreachable", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	copyHeader(w.Header(), resp.Header)
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

var hopHeaders = map[string]bool{
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Te": true, "Trailer": true, "Transfer-Encoding": true,
	"Upgrade": true, "Content-Length": true, "Host": true,
}

func copyHeader(dst, src http.Header) {
	drop := map[string]bool{}
	for _, v := range src.Values("Connection") {
		for name := range strings.SplitSeq(v, ",") {
			drop[textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(name))] = true
		}
	}
	for k, vs := range src {
		ck := textproto.CanonicalMIMEHeaderKey(k)
		if hopHeaders[ck] || drop[ck] {
			continue
		}
		dst[ck] = append([]string(nil), vs...)
	}
}
