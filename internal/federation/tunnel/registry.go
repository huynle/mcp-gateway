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
	if old != nil {
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

// conn is one live tunnel connection (gateway side).
type conn struct {
	tunnelID string
	ws       *websocket.Conn
	limits   Limits
	life     context.Context
	cancel   context.CancelFunc
	slots    chan struct{}
	// epoch is this connection's holder epoch (relay only; 0 = not
	// recorded yet).
	epoch atomic.Int64

	mu      sync.Mutex
	nextID  uint64
	streams map[uint64]*stream
	closed  bool
}

func newConn(tunnelID string, ws *websocket.Conn, l Limits) *conn {
	life, cancel := context.WithCancel(context.Background())
	return &conn{
		tunnelID: tunnelID, ws: ws, limits: l, life: life, cancel: cancel,
		slots: make(chan struct{}, l.MaxStreams), streams: map[uint64]*stream{},
	}
}

// close ends the connection with a close code and fails every stream.
func (c *conn) close(code websocket.StatusCode, reason string) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	streams := c.streams
	c.streams = map[uint64]*stream{}
	c.mu.Unlock()
	for _, s := range streams {
		s.fail(newError(ClassOffline, "disconnected", nil))
	}
	// Send the close frame (with its code) before cancelling the read
	// context: cancelling a pending Read tears the connection down without
	// one. Close waits for the peer's reply (bounded by the library), so
	// it runs in the background and does not hold up the caller.
	go func() {
		_ = c.ws.Close(code, reason)
		c.cancel()
	}()
}

func (c *conn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// open allocates a stream, bounded by MaxStreams.
func (c *conn) open(ctx context.Context) (*stream, error) {
	select {
	case c.slots <- struct{}{}:
	default:
		return nil, newError(ClassBusy, "", nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		<-c.slots
		return nil, newError(ClassOffline, "", nil)
	}
	c.nextID++
	s := newStream(c, c.nextID, ctx)
	c.streams[s.id] = s
	return s, nil
}

// forget removes a finished stream and frees its slot (once per stream).
func (c *conn) forget(s *stream) {
	c.mu.Lock()
	if c.streams[s.id] == s {
		delete(c.streams, s.id)
	}
	c.mu.Unlock()
	<-c.slots
}

func (c *conn) stream(id uint64) *stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.streams[id]
}

func (c *conn) send(f *frame) error { return writeFrame(c.life, c.ws, f) }

// cancelStream tells the client to abandon a stream (best effort, async).
func (c *conn) cancelStream(id uint64) {
	go func() { _ = c.send(&frame{Type: frameCancel, ID: id}) }()
}

// dispatch routes one frame from the client to its stream.
func (c *conn) dispatch(f *frame) {
	s := c.stream(f.ID)
	if s == nil {
		return // already finished or cancelled
	}
	switch f.Type {
	case frameHead:
		if f.Status < 100 || f.Status > 999 {
			s.fail(newError(ClassUnreachable, "bad_status", nil))
			c.cancelStream(s.id)
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
