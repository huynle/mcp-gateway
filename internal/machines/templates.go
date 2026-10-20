package machines

// portalTemplates are the machine pages (the shared shell from package
// nav: page.head, nav). No inline script or style (CSP).
const portalTemplates = `
{{define "head"}}<!doctype html>
<html lang="en">
<head>
  {{template "page.head"}}
  <title>{{.Title}} · MCP Gateway</title>
</head>
<body>
{{template "nav" navData}}
<main>
<h1>{{.Title}}</h1>
{{end}}

{{define "foot"}}
</main>
</body>
</html>
{{end}}

{{define "message"}}{{template "head" .}}
<p class="{{if .OK}}ok{{else}}muted{{end}}">{{.Message}}</p>
<p><a class="btn" href="/machines">Machines</a></p>
{{template "foot" .}}{{end}}

{{define "activate"}}{{template "head" .}}
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
{{with .Request}}
<p><strong>A machine asks to connect to your account.</strong> Approve only if you just ran <code>mcp-gateway login</code> yourself and the details below match what it printed. Approving makes the machine yours: it can register MCP servers under your account and serve them to the gateway, until you revoke it.</p>
<table>
  <tbody>
    <tr><th>Code</th><td><code>{{.Code}}</code></td></tr>
    <tr><th>Machine name</th><td><strong>{{.Name}}</strong></td></tr>
    <tr><th>Key fingerprint</th><td><code class="fingerprint">{{.Fingerprint}}</code> <span class="muted">(full: <code>{{.FullFingerprint}}</code>)</span></td></tr>
    <tr><th>Requested from</th><td><code>{{.IP}}</code></td></tr>
    <tr><th>Client version</th><td>{{if .ClientVersion}}{{.ClientVersion}}{{else}}<span class="muted">not given</span>{{end}}</td></tr>
    <tr><th>Requested at</th><td>{{fmtTime .Requested}} <span class="muted">(expires {{fmtTime .Expires}})</span></td></tr>
  </tbody>
</table>
<p class="muted">Compare the fingerprint with the one <code>mcp-gateway login</code> shows. If someone sent you this code or link, deny it.</p>
<form method="post" action="/activate" class="inline">
  <input type="hidden" name="_csrf" value="{{$.CSRF}}">
  <input type="hidden" name="request_id" value="{{.ID}}">
  <input type="hidden" name="code" value="{{.Code}}">
  <button class="btn primary" type="submit" name="action" value="approve">Approve</button>
  <button class="btn danger" type="submit" name="action" value="deny">Deny</button>
</form>
{{else}}
<p class="muted">Enter the code <code>mcp-gateway login</code> printed on your machine.</p>
<form method="post" action="/activate">
  <input type="hidden" name="_csrf" value="{{.CSRF}}">
  <input type="hidden" name="action" value="lookup">
  <label>Code <input name="code" value="{{.Code}}" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="16" required placeholder="BCDF-GHJK"></label>
  <button class="btn primary" type="submit">Continue</button>
</form>
{{end}}
{{template "foot" .}}{{end}}

{{define "machineRows"}}
<table>
  <thead><tr><th>Name</th>{{if .Admin}}<th>Owner</th>{{end}}<th>Fingerprint</th><th>Status</th><th>Created</th><th>Last seen</th><th>Last IP</th><th>Servers</th><th></th></tr></thead>
  <tbody>
  {{range .Rows}}
  <tr>
    <td><strong>{{.Name}}</strong>{{if .ClientVersion}} <span class="muted">{{.ClientVersion}}</span>{{end}}</td>
    {{if $.Admin}}<td>{{.OwnerName}}</td>{{end}}
    <td><code class="fingerprint">{{fp .Fingerprint}}</code></td>
    <td>{{if .RevokedAt}}<span class="pill revoked">revoked</span> <span class="muted">{{.RevokeReason}}</span>{{else if .Online}}<span class="pill active">connected</span>{{else}}<span class="pill none">offline</span>{{end}}</td>
    <td>{{fmtTime .CreatedAt}}</td>
    <td>{{fmtTimeP .LastSeenAt}}</td>
    <td>{{if .LastIP}}<code>{{.LastIP}}</code>{{end}}</td>
    <td>{{range $i, $s := .Servers}}{{if $i}}, {{end}}{{$s}}{{end}}</td>
    <td class="actions">{{if not .RevokedAt}}<form method="post" action="{{$.Prefix}}/machines/{{.ID}}/revoke"><input type="hidden" name="_csrf" value="{{$.CSRF}}"><button class="btn small danger" type="submit">Revoke</button></form>{{end}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{end}}

{{define "machines"}}{{template "head" .}}
{{if .Notice}}<p class="ok">{{.Notice}}</p>{{end}}
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
<p class="muted">Machines run <code>mcp-gateway up</code> to connect the MCP servers listed in their <code>~/.config/mcp-gateway/config.yaml</code>. Connect one with <code>mcp-gateway login --gateway {{.BaseURL}}</code> and approve it here; revoke a machine to cut it off at once.{{if .IsAdmin}} Admins see every machine under <a href="/admin/machines">All machines</a>.{{end}}</p>
{{if .Machines}}{{template "machineRows" (rowsOf .Machines .CSRF false)}}{{else}}<p class="muted">No machine is connected to your account.</p>{{end}}

<h2 id="codes">Enrollment codes</h2>
<p class="muted">A one-time code enrolls a headless machine without a browser: <code>mcp-gateway login --enroll-code mge_…</code>. The machine becomes yours. Keep codes short-lived and revoke unused ones.</p>
{{with .NewCode}}
<div class="ok">
  <p><strong>Enrollment code created{{if .Label}} for “{{.Label}}”{{end}}.</strong> Copy it now: it is shown only once and expires {{fmtTime .Expires}}.</p>
  <div class="copyable"><pre class="token" id="enroll-code">{{.Code}}</pre><button type="button" class="btn small" data-copy="text" data-copy-target="enroll-code" hidden>Copy</button></div>
  <div class="copyable"><pre id="enroll-command">{{.Command}}</pre><button type="button" class="btn small" data-copy="text" data-copy-target="enroll-command" hidden>Copy</button></div>
</div>
{{end}}
<form method="post" action="/machines/codes">
  <input type="hidden" name="_csrf" value="{{.CSRF}}">
  <label>Label <input name="label" maxlength="100" placeholder="ci runner"></label>
  <label>Valid for <select name="ttl"><option value="1h">1 hour</option><option value="24h" selected>24 hours</option><option value="7d">7 days</option></select></label>
  <button class="btn primary" type="submit">Create enrollment code</button>
</form>
{{if .Codes}}
<table>
  <thead><tr><th>Label</th><th>Created</th><th>Expires</th><th>State</th><th></th></tr></thead>
  <tbody>
  {{range .Codes}}
  <tr>
    <td>{{if .Label}}{{.Label}}{{else}}<span class="muted">no label</span>{{end}}</td>
    <td>{{fmtTime .CreatedAt}}</td>
    <td>{{fmtTime .ExpiresAt}}</td>
    <td><span class="pill">{{.State}}</span></td>
    <td class="actions">{{if eq .State "unused"}}<form method="post" action="/machines/codes/{{.ID}}/revoke"><input type="hidden" name="_csrf" value="{{$.CSRF}}"><button class="btn small danger" type="submit">Revoke</button></form>{{end}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{end}}
{{template "foot" .}}{{end}}

{{define "admin_machines"}}{{template "head" .}}
{{if .Notice}}<p class="ok">{{.Notice}}</p>{{end}}
<p class="muted">Every enrolled machine. Revoking one closes its connection and takes its servers offline; its owner can enroll it again.</p>
{{if .Machines}}{{template "machineRows" (adminRowsOf .Machines .CSRF)}}{{else}}<p class="muted">No machine is enrolled.</p>{{end}}
{{template "foot" .}}{{end}}
`

// rowsView feeds the machineRows template.
type rowsView struct {
	Rows   []machineRow
	CSRF   string
	Admin  bool
	Prefix string
}
