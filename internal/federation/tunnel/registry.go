package tunnel

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/coder/websocket"
)

// registry holds the live connection of each tunnel on this replica: at
// most one per tunnel, a newer one replaces the older.
type registry struct {
	mu    sync.Mutex
	conns map[string]*conn
}

func newRegistry() *registry { return &registry{conns: map[string]*conn{}} }

// put makes c the tunnel's live connection and closes the one it replaces.
func (r *registry) put(id string, c *conn) {
	r.mu.Lock()
	old := r.conns[id]
	r.conns[id] = c
	r.mu.Unlock()
	if old != nil && old != c {
		old.close(closeReplaced, "replaced")
	}
}

func (r *registry) get(id string) *conn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.conns[id]
}

// remove forgets c if it is still the tunnel's live connection.
func (r *registry) remove(id string, c *conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conns[id] == c {
		delete(r.conns, id)
	}
}

// drop closes and forgets tunnelID's live connection, if any.
func (r *registry) drop(id string, code websocket.StatusCode, reason string) {
	r.mu.Lock()
	c := r.conns[id]
	delete(r.conns, id)
	r.mu.Unlock()
	if c != nil {
		c.close(code, reason)
	}
}

// link is one WebSocket from a client: a legacy tunnel connection (one
// tunnel) or a machine connection (every tunnel linked to the machine).
// Stream ids are unique per link, so response frames need no tunnel id.
type link struct {
	ws      *websocket.Conn
	machine string // "" for a legacy tunnel connection
	life    context.Context
	cancel  context.CancelFunc

	mu      sync.Mutex
	nextID  uint64
	streams map[uint64]*stream
	views   map[string]*conn // by tunnel id
	closed  bool

	syncMu sync.Mutex // one tunnel-set sync at a time (machine links)
}

func newLink(ws *websocket.Conn, machine string) *link {
	life, cancel := context.WithCancel(context.Background())
	return &link{ws: ws, machine: machine, life: life, cancel: cancel, streams: map[uint64]*stream{}, views: map[string]*conn{}}
}

// close ends the WebSocket with a close code and fails every stream.
func (l *link) close(code websocket.StatusCode, reason string) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	streams := l.streams
	l.streams = map[uint64]*stream{}
	views := l.views
	l.views = map[string]*conn{}
	l.mu.Unlock()
	for _, c := range views {
		c.closed.Store(true)
	}
	for _, s := range streams {
		s.fail(newError(ClassOffline, "disconnected", nil))
	}
	// Send the close frame (with its code) before cancelling the read
	// context: cancelling a pending Read tears the connection down without
	// one. Close waits for the peer's reply (bounded by the library), so
	// it runs in the background and does not hold up the caller.
	go func() {
		_ = l.ws.Close(code, reason)
		l.cancel()
	}()
}

func (l *link) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

func (l *link) send(f *frame) error { return writeFrame(l.life, l.ws, f) }

// viewList returns the link's tunnel views.
func (l *link) viewList() []*conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]*conn, 0, len(l.views))
	for _, c := range l.views {
		out = append(out, c)
	}
	return out
}

// attach adds a view for tunnelID (nil when the link is closed or already
// has one).
func (l *link) attach(tunnelID string, lim Limits) *conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.views[tunnelID] != nil {
		return nil
	}
	c := &conn{tunnelID: tunnelID, l: l, limits: lim, slots: make(chan struct{}, lim.MaxStreams)}
	l.views[tunnelID] = c
	return c
}

// dispatch routes one frame from the client to its stream.
func (l *link) dispatch(f *frame) {
	l.mu.Lock()
	s := l.streams[f.ID]
	l.mu.Unlock()
	if s == nil {
		return // already finished or cancelled
	}
	switch f.Type {
	case frameHead:
		if f.Status < 100 || f.Status > 999 {
			s.fail(newError(ClassUnreachable, "bad_status", nil))
			s.c.cancelStream(s.id)
			return
		}
		s.deliverHead(f)
	case frameData:
		s.push(f.Data)
	case frameEnd:
		if f.Error != "" {
			s.fail(newError(ClassUnreachable, "client_error", nil))
			return
		}
		s.finish()
	}
}

// conn is one tunnel served by a link (gateway side): the link itself for
// a legacy tunnel connection, one of several views of a machine link.
type conn struct {
	tunnelID string
	l        *link
	limits   Limits
	slots    chan struct{}
	// epoch is this connection's holder epoch (relay only; 0 = not
	// recorded yet).
	epoch atomic.Int64
	// closed: the view was detached (or its link closed).
	closed atomic.Bool
}

// newConn is a legacy tunnel connection: a link with its one view.
func newConn(tunnelID string, ws *websocket.Conn, l Limits) *conn {
	return newLink(ws, "").attach(tunnelID, l)
}

// close ends the tunnel's connection. A legacy connection closes its
// WebSocket with the code; a machine view is only detached (the machine's
// other tunnels stay up).
func (c *conn) close(code websocket.StatusCode, reason string) {
	if c.l.machine == "" {
		c.l.close(code, reason)
		return
	}
	c.detach()
}

// detach removes a machine view from its link and fails its streams.
func (c *conn) detach() {
	if c.closed.Swap(true) {
		return
	}
	l := c.l
	l.mu.Lock()
	if l.views[c.tunnelID] == c {
		delete(l.views, c.tunnelID)
	}
	var mine []*stream
	for id, s := range l.streams {
		if s.c == c {
			mine = append(mine, s)
			delete(l.streams, id)
		}
	}
	l.mu.Unlock()
	for _, s := range mine {
		s.fail(newError(ClassOffline, "disconnected", nil))
		c.cancelStream(s.id)
	}
}

func (c *conn) isClosed() bool { return c.closed.Load() || c.l.isClosed() }

// open allocates a stream, bounded by MaxStreams per tunnel.
func (c *conn) open(ctx context.Context) (*stream, error) {
	select {
	case c.slots <- struct{}{}:
	default:
		return nil, newError(ClassBusy, "", nil)
	}
	l := c.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || c.closed.Load() {
		<-c.slots
		return nil, newError(ClassOffline, "", nil)
	}
	l.nextID++
	s := newStream(c, l.nextID, ctx)
	l.streams[s.id] = s
	return s, nil
}

// forget removes a finished stream and frees its slot (once per stream).
func (c *conn) forget(s *stream) {
	l := c.l
	l.mu.Lock()
	if l.streams[s.id] == s {
		delete(l.streams, s.id)
	}
	l.mu.Unlock()
	<-c.slots
}

func (c *conn) send(f *frame) error { return c.l.send(f) }

// cancelStream tells the client to abandon a stream (best effort, async).
func (c *conn) cancelStream(id uint64) {
	go func() { _ = c.send(&frame{Type: frameCancel, ID: id}) }()
}
