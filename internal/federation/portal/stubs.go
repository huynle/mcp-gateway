package portal

import (
	"net/http"

	"github.com/huynle/mcp-gateway/internal/store"
)

func (p *Portal) todo(w http.ResponseWriter, r *http.Request, c caller) {
	p.render(w, r, http.StatusNotImplemented, "message.html", messageData{Title: "Servers", Message: "Not implemented yet."})
}

func (p *Portal) todoS(w http.ResponseWriter, r *http.Request, c caller, _ *store.MCPServer) {
	p.todo(w, r, c)
}

func (p *Portal) newForm(w http.ResponseWriter, r *http.Request, c caller)      { p.todo(w, r, c) }
func (p *Portal) create(w http.ResponseWriter, r *http.Request, c caller)       { p.todo(w, r, c) }
func (p *Portal) createTunnel(w http.ResponseWriter, r *http.Request, c caller) { p.todo(w, r, c) }
func (p *Portal) revokeTunnel(w http.ResponseWriter, r *http.Request, c caller) { p.todo(w, r, c) }

func (p *Portal) detail(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	p.todoS(w, r, c, s)
}
func (p *Portal) setCredential(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	p.todoS(w, r, c, s)
}
func (p *Portal) disconnect(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	p.todoS(w, r, c, s)
}
func (p *Portal) refresh(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	p.todoS(w, r, c, s)
}
func (p *Portal) review(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	p.todoS(w, r, c, s)
}
func (p *Portal) approve(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	p.todoS(w, r, c, s)
}
func (p *Portal) resources(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	p.todoS(w, r, c, s)
}
func (p *Portal) readResource(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	p.todoS(w, r, c, s)
}
func (p *Portal) prompt(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	p.todoS(w, r, c, s)
}
func (p *Portal) editForm(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	p.todoS(w, r, c, s)
}
func (p *Portal) save(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	p.todoS(w, r, c, s)
}
func (p *Portal) delete(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	p.todoS(w, r, c, s)
}
