package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"github.com/coder/websocket"
)

// Wire protocol (version 1, WebSocket subprotocol "mcp-gateway-tunnel.v1").
//
// The tunnel client opens GET ConnectPath with "Authorization: Bearer
// <token>" and upgrades to a WebSocket. Every message is one JSON text
// frame:
//
//	gateway -> client
//	  {"t":"req","id":N,"m":"POST","p":"/mcp?x=1","h":{...},"d":"<base64 body>"}
//	  {"t":"cancel","id":N}
//	client -> gateway
//	  {"t":"head","id":N,"s":200,"h":{...}}
//	  {"t":"data","id":N,"d":"<base64 chunk, at most 32 KiB>"}   (0..n)
//	  {"t":"end","id":N,"e":"<optional error class>"}
//
// Stream ids are chosen by the gateway, unique per connection. A request
// carries its whole body (bounded by Limits.MaxRequestBytes); a response
// streams as head, data*, end, so SSE and streamable HTTP responses flow
// as they are produced. Hop-by-hop headers and Content-Length are dropped
// on both sides. Close codes: 4001 replaced by a newer connection, 4003
// tunnel revoked.
//
// Machine connections (subprotocol "mcp-gateway-machine.v1", GET
// MachineConnectPath with a machine access token, Brain decision
// ldjix4y1) use the same frames over one WebSocket for every tunnel
// linked to the machine. Each req frame names its tunnel:
//
//	{"t":"req","id":N,"tid":"<tunnel id>",...}
//
// Stream ids stay unique per connection, so head, data, end and cancel
// need no tid. The gateway also sends the machine's current tunnel ids
// on connect and whenever they change:
//
//	{"t":"tunnels","ids":["<tunnel id>",...]}
//
// The client may ignore it. Close codes: 4001 replaced by a newer
// connection of the same machine, 4003 machine revoked.
const (
	// ConnectPath is where the gateway mounts Service.Handler.
	ConnectPath = "/tunnel/connect"
	// Subprotocol is the negotiated WebSocket subprotocol.
	Subprotocol = "mcp-gateway-tunnel.v1"
	// MachineConnectPath is where the machines API mounts its connect
	// endpoint (Service.ServeMachine behind the machine token check).
	MachineConnectPath = "/machine/v1/connect"
	// MachineSubprotocol is the machine connection's subprotocol.
	MachineSubprotocol = "mcp-gateway-machine.v1"

	frameRequest = "req"
	frameCancel  = "cancel"
	frameHead    = "head"
	frameData    = "data"
	frameEnd     = "end"
	frameTunnels = "tunnels"

	// maxChunk bounds one data frame's payload.
	maxChunk = 32 << 10
	// gatewayReadLimit bounds one frame read by the gateway (head with
	// headers, or a data chunk).
	gatewayReadLimit = 1 << 20
	// agentReadLimit bounds one frame read by the client (a request with
	// its whole body, base64-encoded).
	agentReadLimit = 32 << 20
	// writeTimeout bounds one frame write.
	writeTimeout = 10 * time.Second

	closeReplaced websocket.StatusCode = 4001
	closeRevoked  websocket.StatusCode = 4003
)

type frame struct {
	Type   string      `json:"t"`
	ID     uint64      `json:"id,omitempty"`
	Method string      `json:"m,omitempty"`
	Path   string      `json:"p,omitempty"`
	Header http.Header `json:"h,omitempty"`
	Status int         `json:"s,omitempty"`
	Data   []byte      `json:"d,omitempty"`
	Error  string      `json:"e,omitempty"`
	// Tunnel names a machine connection's tunnel on req frames.
	Tunnel string `json:"tid,omitempty"`
	// IDs lists a machine's tunnel ids (tunnels frames).
	IDs []string `json:"ids,omitempty"`
}

var errBadFrame = errors.New("tunnel: malformed frame")

func writeFrame(ctx context.Context, ws *websocket.Conn, f *frame) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	return ws.Write(ctx, websocket.MessageText, b)
}

func readFrame(ctx context.Context, ws *websocket.Conn) (*frame, error) {
	typ, b, err := ws.Read(ctx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageText {
		return nil, errBadFrame
	}
	var f frame
	if err := json.Unmarshal(b, &f); err != nil || f.Type == "" {
		return nil, errBadFrame
	}
	return &f, nil
}

// hopHeaders are connection-specific (RFC 9110 §7.6.1) or recomputed by
// the receiving side.
var hopHeaders = map[string]bool{
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Te": true, "Trailer": true, "Transfer-Encoding": true,
	"Upgrade": true, "Content-Length": true, "Host": true,
}

// cleanHeader copies h without hop-by-hop headers (including those named
// in Connection).
func cleanHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	drop := map[string]bool{}
	for _, v := range h.Values("Connection") {
		for name := range strings.SplitSeq(v, ",") {
			drop[textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(name))] = true
		}
	}
	for k, vs := range h {
		ck := textproto.CanonicalMIMEHeaderKey(k)
		if hopHeaders[ck] || drop[ck] {
			continue
		}
		out[ck] = append([]string(nil), vs...)
	}
	return out
}
