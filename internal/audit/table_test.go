package audit_test

import (
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/audit"
)

// The audit table is wide (nine columns, UUIDs). It scrolls inside its own
// box so the page never overflows the viewport; ids are a compact
// monospace list whose values ellipsize with the full value on hover.
func TestAuditTableScrollsAndClipsIDs(t *testing.T) {
	rows := sampleRows()
	rows[0].ApprovalID = "a9c1f7e2-1111-4a6b-8c7d-9e0f1a2b3c4d"
	rows[0].OperationID = "0e1d2c3b-2222-4a6b-8c7d-9e0f1a2b3c4d"
	rows[0].PolicyVersion = "pv-3"
	f := &fakeReader{rows: rows}
	body := get(t, audit.AdminSearchHandler(f, identity(alice, true)), "/admin/audit").Body.String()

	scroll, _, ok := strings.Cut(body[strings.Index(body, `<div class="table-scroll"`)+1:], "</div>")
	if !ok || !strings.Contains(body, `<div class="table-scroll"`) {
		t.Fatalf("table not wrapped in a scroll container:\n%s", body)
	}
	if !strings.Contains(scroll, "<table") || !strings.Contains(scroll, "</table>") {
		t.Errorf("scroll container does not hold the table:\n%s", scroll)
	}
	for _, want := range []string{
		`<ul class="ids">`,
		`<li><span class="k">request</span><span class="v" title="req-alice-0001">req-alice-0001</span></li>`,
		`<li><span class="k">token</span><span class="v" title="tok-1">tok-1</span></li>`,
		`<li><span class="k">approval</span><span class="v" title="a9c1f7e2-1111-4a6b-8c7d-9e0f1a2b3c4d">a9c1f7e2-1111-4a6b-8c7d-9e0f1a2b3c4d</span></li>`,
		`<li><span class="k">operation</span><span class="v" title="0e1d2c3b-2222-4a6b-8c7d-9e0f1a2b3c4d">`,
		`<li><span class="k">policy</span><span class="v" title="pv-3">pv-3</span></li>`,
		// the admin's user column: monospace, clipped, full id on hover
		`<span class="mono clip" title="` + alice + `">` + alice + `</span>`,
		// resource values ellipsize with the full (escaped) value on hover
		`<dd title="acme/api">acme/api</dd>`,
		`<dd title="&lt;script&gt;alert(1)&lt;/script&gt;">&lt;script&gt;alert(1)&lt;/script&gt;</dd>`,
		`<td class="nowrap">2026-10-08 09:30:00Z</td>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("audit table lacks %s", want)
		}
	}
	if strings.Contains(body, "<br>") {
		t.Errorf("ids still separated by <br>:\n%s", body)
	}
}

// The filter form's submit is a styled button, like every other form.
func TestAuditFilterButtonIsStyled(t *testing.T) {
	body := get(t, audit.ActivityHandler(&fakeReader{}, identity(alice, false)), "/activity").Body.String()
	if !strings.Contains(body, `<button class="btn primary" type="submit">Filter</button>`) {
		t.Errorf("filter button not styled:\n%s", body)
	}
}
