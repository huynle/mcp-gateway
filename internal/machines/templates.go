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
{{end}}

{{define "foot"}}
</main>
{{template "footer"}}
</body>
</html>
{{end}}

{{define "message"}}{{template "head" .}}
<div class="auth">
<section class="panel">
  <h1>{{.Title}}</h1>
  <p class="{{if .OK}}ok{{else}}notice{{end}}">{{.Message}}</p>
  <div class="panel-foot">{{if .Harness}}<a class="btn" href="/harnesses">{{icon "harnesses"}}Harnesses</a>{{else}}<a class="btn" href="/machines">{{icon "machines"}}Machines</a>{{end}}</div>
</section>
</div>
{{template "foot" .}}{{end}}

{{define "activate"}}{{template "head" .}}
<div class="auth">
<section class="panel">
  <h1>{{.Title}}</h1>
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}
{{with .Request}}
  <p><strong>A machine asks to connect to your account.</strong> Approve only if you just ran <code>mcp-gateway login</code> yourself and the details below match what it printed. Approving makes the machine yours: it can register MCP servers under your account and serve them to the gateway, until you revoke it.</p>
  <dl class="kv">
    <dt>Code</dt><dd><code>{{.Code}}</code></dd>
    <dt>Machine name</dt><dd><strong>{{.Name}}</strong></dd>
    <dt>Key fingerprint</dt><dd><code class="fingerprint">{{.Fingerprint}}</code><br><span class="muted">full: <code class="clip" title="{{.FullFingerprint}}">{{.FullFingerprint}}</code></span></dd>
    <dt>Requested from</dt><dd><code>{{.IP}}</code></dd>
    <dt>Client version</dt><dd>{{if .ClientVersion}}{{.ClientVersion}}{{else}}<span class="muted">not given</span>{{end}}</dd>
    <dt>Requested at</dt><dd>{{fmtTime .Requested}}<br><span class="muted">expires {{fmtTime .Expires}}</span></dd>
  </dl>
  <p class="callout warn">Compare the fingerprint with the one <code>mcp-gateway login</code> shows. If someone sent you this code or link, deny it.</p>
  <form method="post" action="/activate">
    <input type="hidden" name="_csrf" value="{{$.CSRF}}">
    <input type="hidden" name="request_id" value="{{.ID}}">
    <input type="hidden" name="code" value="{{.Code}}">
    <div class="panel-foot">
      <button class="btn primary" type="submit" name="action" value="approve">{{icon "check"}}Approve</button>
      <button class="btn danger" type="submit" name="action" value="deny">{{icon "x"}}Deny</button>
    </div>
  </form>
{{else with .Harness}}
  <p><strong>A harness asks to sign in to the MCP gateway as you.</strong> Allow only if you just started the sign-in yourself (for example in a harness on a remote host) and the details below match what it printed. Allowing lets it use the tools your role allows, under policy and approvals, until you disconnect it on the Harnesses page.</p>
  <dl class="kv">
    <dt>Code</dt><dd><code>{{.UserCode}}</code></dd>
    <dt>Harness</dt><dd><strong>{{.ClientName}}</strong><br><span class="muted"><code>{{.ClientID}}</code></span></dd>
    <dt>It will be able to</dt><dd>{{range .Scopes}}{{.}}<br>{{end}}</dd>
    <dt>Tokens for</dt><dd><code>{{.Resource}}</code></dd>
    <dt>Requested from</dt><dd><code>{{.RequestIP}}</code></dd>
    <dt>User-Agent</dt><dd>{{if .UserAgent}}<code class="clip" title="{{.UserAgent}}">{{.UserAgent}}</code>{{else}}<span class="muted">not given</span>{{end}}</dd>
    <dt>Requested at</dt><dd>{{fmtTime .CreatedAt}}<br><span class="muted">expires {{fmtTime .ExpiresAt}}</span></dd>
  </dl>
  <p class="callout warn">Check that the address and User-Agent are those of the host you are signing in from. If someone sent you this code or link, deny it.</p>
  <form method="post" action="/activate">
    <input type="hidden" name="_csrf" value="{{$.CSRF}}">
    <input type="hidden" name="request_id" value="{{.ID}}">
    <input type="hidden" name="code" value="{{.UserCode}}">
    <p class="hint">By allowing, you let this harness act as you under the <a href="/terms">Terms of Service</a> and the <a href="/privacy">Privacy Policy</a>.</p>
    <div class="panel-foot">
      <button class="btn primary" type="submit" name="action" value="approve">{{icon "check"}}Allow</button>
      <button class="btn danger" type="submit" name="action" value="deny">{{icon "x"}}Deny</button>
    </div>
  </form>
{{else}}
  <p class="muted">Enter the code <code>mcp-gateway login</code> printed on your machine, or the code your harness showed.</p>
  <form method="post" action="/activate" class="stack">
    <input type="hidden" name="_csrf" value="{{.CSRF}}">
    <input type="hidden" name="action" value="lookup">
    <label>Code <input class="code-input" name="code" value="{{.Code}}" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="16" required placeholder="BCDF-GHJK">
      <span class="hint">Eight letters, valid for 10 minutes after it is shown.</span></label>
    <div class="panel-foot"><button class="btn primary" type="submit">Continue</button></div>
  </form>
{{end}}
</section>
</div>
{{template "foot" .}}{{end}}

{{define "machineRows"}}
<div class="table-scroll">
<table>
  <thead><tr><th>Name</th>{{if .Admin}}<th>Owner</th>{{end}}<th>Fingerprint</th><th>Status</th><th>Created</th><th>Last seen</th><th>Last IP</th><th>Servers</th><th><span class="sr-only">Actions</span></th></tr></thead>
  <tbody>
  {{range .Rows}}
  <tr>
    <td><strong>{{.Name}}</strong>{{if .ClientVersion}} <span class="muted">{{.ClientVersion}}</span>{{end}}</td>
    {{if $.Admin}}<td>{{.OwnerName}}</td>{{end}}
    <td><code class="fingerprint">{{fp .Fingerprint}}</code></td>
    <td>{{if .RevokedAt}}<span class="pill revoked">revoked</span> <span class="muted">{{.RevokeReason}}</span>{{else if .Online}}<span class="pill active">connected</span>{{else}}<span class="pill none">offline</span>{{end}}</td>
    <td class="nowrap">{{fmtTime .CreatedAt}}</td>
    <td class="nowrap">{{fmtTimeP .LastSeenAt}}</td>
    <td>{{if .LastIP}}<code>{{.LastIP}}</code>{{end}}</td>
    <td>{{range $i, $s := .Servers}}{{if $i}}, {{end}}{{$s}}{{end}}</td>
    <td class="actions">{{if not .RevokedAt}}<form class="inline" method="post" action="{{$.Prefix}}/machines/{{.ID}}/revoke"><input type="hidden" name="_csrf" value="{{$.CSRF}}"><button class="btn small danger" type="submit">Revoke</button></form>{{end}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
</div>
{{end}}

{{define "machines"}}{{template "head" .}}
<header class="page-head">
  <div>
    <h1>{{.Title}}</h1>
    <p class="page-desc">Machines run <code>mcp-gateway up</code> to connect the MCP servers listed in their <code>~/.config/mcp-gateway/config.yaml</code>. Connect one with <code>mcp-gateway login --gateway {{.BaseURL}}</code> and approve it here; revoke a machine to cut it off at once.{{if .IsAdmin}} Admins see every machine under <a href="/admin/machines">All machines</a>.{{end}}</p>
  </div>
  <div class="page-actions"><a class="btn primary" href="/activate">{{icon "plus"}}Connect a machine</a></div>
</header>
{{if .Notice}}<p class="ok">{{.Notice}}</p>{{end}}
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}

<section class="section">
  <div class="section-head"><div><h2>My machines</h2></div></div>
  {{if .Machines}}{{template "machineRows" (rowsOf .Machines .CSRF false)}}{{else}}
  <div class="empty">{{icon "machines"}}<strong>No machine is connected to your account.</strong><p>Run <code>mcp-gateway login --gateway {{.BaseURL}}</code> on the machine, then enter the code it prints under Connect a machine.</p><a class="btn primary" href="/activate">{{icon "plus"}}Connect a machine</a></div>
  {{end}}
</section>

<section class="section">
  <div class="section-head">
    <div><h2 id="codes">Enrollment codes</h2><p>A one-time code enrolls a headless machine without a browser: <code>mcp-gateway login --enroll-code mge_…</code>. The machine becomes yours. Keep codes short-lived and revoke unused ones.</p></div>
  </div>
{{with .NewCode}}
  <section class="panel secret-reveal">
    <div class="panel-head"><h3>Enrollment code created{{if .Label}} for “{{.Label}}”{{end}}</h3></div>
    <p class="callout warn">Copy it now: it is shown only once and expires {{fmtTime .Expires}}.</p>
    <div class="copyable"><pre class="token" id="enroll-code">{{.Code}}</pre><button type="button" class="btn small" data-copy="text" data-copy-target="enroll-code" hidden>{{icon "copy"}}Copy</button></div>
    <p class="hint">On the machine, run:</p>
    <div class="copyable"><pre id="enroll-command">{{.Command}}</pre><button type="button" class="btn small" data-copy="text" data-copy-target="enroll-command" hidden>{{icon "copy"}}Copy</button></div>
  </section>
{{end}}
  <section class="panel">
    <div class="panel-head"><h3>New enrollment code</h3></div>
    <form method="post" action="/machines/codes" class="stack">
      <input type="hidden" name="_csrf" value="{{.CSRF}}">
      <div class="row">
        <label>Label <input name="label" maxlength="100" placeholder="ci runner"></label>
        <label>Valid for <select name="ttl"><option value="1h">1 hour</option><option value="24h" selected>24 hours</option><option value="7d">7 days</option></select></label>
      </div>
      <div class="form-actions"><button class="btn" type="submit">{{icon "plus"}}Create enrollment code</button></div>
    </form>
  </section>
{{if .Codes}}
  <div class="table-wrap">
  <table>
    <thead><tr><th>Label</th><th>Created</th><th>Expires</th><th>State</th><th><span class="sr-only">Actions</span></th></tr></thead>
    <tbody>
    {{range .Codes}}
    <tr>
      <td>{{if .Label}}{{.Label}}{{else}}<span class="muted">no label</span>{{end}}</td>
      <td class="nowrap">{{fmtTime .CreatedAt}}</td>
      <td class="nowrap">{{fmtTime .ExpiresAt}}</td>
      <td><span class="pill {{if eq .State "unused"}}pending{{else if eq .State "used"}}consumed{{else}}{{.State}}{{end}}">{{.State}}</span></td>
      <td class="actions">{{if eq .State "unused"}}<form class="inline" method="post" action="/machines/codes/{{.ID}}/revoke"><input type="hidden" name="_csrf" value="{{$.CSRF}}"><button class="btn small danger" type="submit">Revoke</button></form>{{end}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
{{end}}
</section>
<script src="{{asset "copy.js"}}" defer></script>
{{template "foot" .}}{{end}}

{{define "admin_machines"}}{{template "head" .}}
<header class="page-head">
  <div>
    <h1>{{.Title}}</h1>
    <p class="page-desc">Every enrolled machine. Revoking one closes its connection and takes its servers offline; its owner can enroll it again.</p>
  </div>
</header>
{{if .Notice}}<p class="ok">{{.Notice}}</p>{{end}}
<section class="section">
  {{if .Machines}}{{template "machineRows" (adminRowsOf .Machines .CSRF)}}{{else}}
  <div class="empty">{{icon "allmachines"}}<strong>No machine is enrolled.</strong><p>Machines appear here once a user connects one with <code>mcp-gateway login</code>.</p></div>
  {{end}}
</section>
{{template "foot" .}}{{end}}
`

// rowsView feeds the machineRows template.
type rowsView struct {
	Rows   []machineRow
	CSRF   string
	Admin  bool
	Prefix string
}
