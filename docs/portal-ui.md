# Portal UI: shell, design system and components

Every portal page (packages `portal`, `tokens`, `approvals`, `ledger`, `connections`, `authserver`, `policy`, `audit`, `secrets`, `machines`, `federation/portal`, `federation/admin`, `federation/elicit`) is server-rendered with Go templates + htmx on one shell owned by `internal/portal/nav` and one stylesheet, `internal/portal/static/portal.css`. Modules keep their own templates (decisions 7datr7x4, u46t7kmq, k5nlscm9); they share the head, the sidebar, the footer, the stylesheet and the components below. The look is a "dev-tool console": neutral surfaces, one teal accent, IBM Plex Sans / Plex Mono, a grouped left sidebar.

## A module's layout

```html
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
```

The layout does **not** render the `<h1>`: each page opens with its own page header, so it can carry a description, breadcrumbs and actions (see below).

Parse the template set with `nav.Setup(template.New(""))` (it registers `navData`, `asset`, `icon` and the partials) and render with `nav.Execute`. Modules that build their FuncMap themselves add `nav.Funcs()` (or at least `nav.AssetFuncName: static.URL, nav.IconFuncName: nav.Icon`) before parsing.

- `page.head`: meta tags, `theme.js` (render-blocking, so a stored theme is applied before the first paint), `portal.css`, `htmx.min.js` (deferred).
- `nav`, signed in: a hidden checkbox (`#nav-drawer`), a top bar with a menu button (narrow screens only) and the **sidebar**: brand, `<nav class="site-nav">` with the link groups (`nav.Groups`: My account; Access: Tokens, Harnesses, Machines; Integrations: Connections, Servers, Secrets; Activity: Approvals, Operations, Activity; plus `nav.AdminGroup` for admins), and at its foot the user block, the theme toggle and sign-out. Below 64rem the sidebar is an off-canvas drawer opened by the menu button (CSS only). Signed out: a slim top bar with the brand and the theme toggle.
- `footer`: Privacy Policy, Terms of Service, Support, Install CLI. Every layout renders it after `</main>`.
- No `<style>` blocks or `style=` attributes in templates, no inline event handlers beyond the existing `onsubmit` confirms (CSP). Rules go into `portal.css`; page-specific sheets (`review.css`) sit next to it.

Drift is caught by tests: `navtest.AssertShell` (called from each module's `shell_test.go`) checks a rendered page links the shared stylesheet and theme script and has the toggle and `<main>`; `navtest.Member` / `navtest.Admin` pin the sidebar links in order; `TestEveryLayoutUsesTheSharedHead` (internal/portal) scans every `templates/*.html` under `internal/`.

## Icons

`{{icon "name"}}` renders an inline, `aria-hidden` SVG (24×24, stroked in `currentColor`) from `internal/portal/nav/icons.go`; an unknown name is a template error. Use them in buttons (`<button class="btn">{{icon "plus"}}Add server</button>`), empty states and the nav. Names: the nav icons (`account tokens harnesses machines connections servers secrets approvals operations activity settings users roles allservers allmachines audit vendorapps`) and `plus copy external arrow-left warning info check x search inbox sun moon system menu signout brand`. Add new ones to the map (hand-drawn, no copied icon sets).

## Page structure

```html
<header class="page-head">
  <div>
    <p class="crumbs"><a href="/servers">Servers</a><span class="sep">/</span>{{.Name}}</p>  <!-- detail pages only -->
    <h1>{{.Title}}</h1>
    <p class="page-desc">One or two sentences: what this page is for.</p>
  </div>
  <div class="page-actions"><a class="btn primary" href="/servers/new">{{icon "plus"}}Add server</a></div>
</header>

<section class="section">
  <div class="section-head">
    <div><h2>My servers</h2><p>Optional one-line explanation.</p></div>
    <div class="btn-row">…optional actions…</div>
  </div>
  …table / panels / empty state…
</section>
```

- Primary page action: top right in `.page-actions` (`.btn.primary`). Secondary actions: plain `.btn`.
- Sub-pages of one area use tabs: `<nav class="tabs" aria-label="…"><a href="…" aria-current="page">…</a>…</nav>` (`.subnav` is the same style).
- A page whose purpose is one decision or one form (sign-in, consent, activate a machine, a one-off confirmation) wraps it in `<div class="auth"><div class="panel">…</div></div>` to centre it.

## Components (classes in portal.css)

| Need | Markup |
|---|---|
| Card / panel | `<section class="panel">` with optional `<div class="panel-head"><h2>…</h2>…badge or button…</div>` and `<div class="panel-foot">…buttons…</div>` at the bottom. `.card` is an alias. `.panel.flush` drops the padding (for a table or list inside, with `.panel-head` as a bar). `.narrow` caps the width |
| Panels side by side | `<div class="grid grid-2">` (or `.grid` for auto-fill tiles) |
| Stat tiles | `<div class="stats"><div class="stat"><div class="stat-label">Servers</div><div class="stat-value">4</div></div>…</div>` |
| Table | tables are plain **grids**: every cell outlined, square corners, a grey header row (normal case), alternate-row shading, compact rows (~34px). A plain `<table>` in `<main>` already looks like this; wrap it in `<div class="table-wrap">` (or `.table-scroll` for wide tables: min-width 48rem, scrolls inside its box, sticky header). Inside cells, values are plain text: a `.pill` is a coloured word with a dot (no fill), `<code>` has no chip box, and buttons/selects/inputs shrink to row height. `td.actions` right-aligns row buttons; `td.num` right-aligns numbers; `.mono`, `.nowrap`, `.clip` (one line + ellipsis, full value in `title`), `ul.ids` for identifier lists |
| Key/value | an unclassed `<dl>` or `<dl class="kv">` renders as a bordered two-column list; `dl.args` for tool arguments |
| Linked rows | `<ul class="list"><li>…left…<span>…right…</span></li></ul>` |
| Status | `<span class="pill {{.Status}}">{{.Status}}</span>`: a dot badge coloured by class: green `active default approved consumed succeeded online ok enabled connected`; red `revoked expired needs_reconnect denied disabled failed unresolved error blocked`; amber `pending in_progress unknown waiting warn review`; teal `company accent published`; grey `none neutral` (or no modifier). `.pill.plain` hides the dot. `.badge` / `a.badge` is the amber "needs attention" chip |
| Callouts | `<p class="callout ok|warn|danger|info">`; the bare classes `ok`, `notice` (warn), `error` (danger), `info` on a block element (`p div section aside form ul`) are the same callouts; on inline elements (`span td li small strong em b dd`) they only colour the text |
| Empty state | `<div class="empty">{{icon "servers"}}<strong>No servers yet</strong><p>What would appear here and how to get started.</p><a class="btn primary" href="…">…</a></div>` (`p.empty` for a one-line muted placeholder) |
| Buttons | `.btn` (secondary), `.btn.primary`, `.btn.danger` (outline, fills on hover), `.btn.danger.solid`, `.btn.ghost`, `.btn.small`, `.btn.block`; group them in `.btn-row`, `.form-actions`, `.actions` or `.panel-foot` (gap, no margins). Every `<button>` without a class looks like `.btn` |
| Forms | `<form class="stack">` (vertical, max 34rem; `.stack.wide` for full width) with `<label>Label <input …><span class="hint">Help.</span></label>`; `.row` for inline fields; `fieldset` + `legend` for groups; `label.check` for a checkbox/radio with text; `label.switch-row` + `input.switch[role=switch]` for toggles; `.seg` for a segmented radio group; `form.filters` for a filter bar above a table |
| Code and secrets | `<pre>` / `<code>`; copyable: `<div class="copyable"><pre id="X">…</pre><button type="button" class="btn small" data-copy="text" data-copy-target="X" hidden>{{icon "copy"}}Copy</button></div>` plus `<script src="{{asset "copy.js"}}" defer></script>`; `.token` for a one-time secret |
| Disclosure | `<details><summary>…</summary>…</details>` (chevron added by CSS); `<details class="panel">` for a collapsible card |
| Danger zone | `<section class="danger-zone"><h3>Delete …</h3><p class="muted">…</p>…</section>` at the end of a page |
| Tabs | `.tabs` / `.subnav` with `aria-current="page"`; CSS-only install tabs: `.install-tabs` (radio + label + `.install-panel` siblings) |
| Misc | `.muted`, `.hint`, `.sr-only`, `.push` (margin-left auto in a flex row), `.prose` / `.legal` (readable width), `.hero` + `.lede` + `.eyebrow` (public home), `.avatar` |

Rules of thumb: one primary button per view; destructive actions are `.btn.danger` and keep their `onsubmit="return confirm(…)"`; every list that can be empty gets an `.empty` state saying what would appear and how to get started; identifiers are `.mono` and, when clipped, carry the full value in `title`.

## Theme and palette

- Colours are CSS custom properties: `--bg` (page), `--panel` (cards, tables, inputs), `--surface` (sidebar, table heads, code), `--fg`, `--muted`, `--line`, `--line-strong`, `--input-border`, `--accent`/`--accent-fg`/`--accent-soft`, `--danger`/`--danger-fg`/`--danger-soft`, `--ok`/`--ok-soft`, `--warn`/`--warn-soft`, `--focus`, `--shadow`. Use the variables, never literal colours.
- `:root` is the light palette, `:root[data-theme="dark"]` the dark one, and `@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) }` repeats the dark palette for the system setting.
- `theme.js` reads `localStorage["mcp-gateway-theme"]` (`light` or `dark`; absent = system) and sets or removes `<html data-theme>`. The toggle (sidebar foot, or the public top bar) is three icon buttons (`data-theme-choice`, `aria-pressed`, a screen-reader label) in a labelled group (`role="group"`, `aria-label="Color theme"`), rendered `hidden` and revealed by the script. A change in another tab is followed through the `storage` event. Without JavaScript the toggle stays hidden and the page follows the system setting.
- `palette_test.go` checks that both palettes define the same variables, that the system copy equals the dark palette, and WCAG AA contrast: 4.5:1 for text and status colours on `--bg`, `--panel` and `--surface`, for button labels and for each status colour (and `--fg`) on its `-soft` fill; 3:1 for input borders and the focus ring.

## Fonts

IBM Plex Sans (400/500/600) and IBM Plex Mono (400/500), Latin subset, self-hosted as woff2 in `internal/portal/static/fonts/` (SIL Open Font License 1.1; licence texts `OFL-plex-sans.txt`, `OFL-plex-mono.txt` next to them; listed in `THIRD_PARTY_NOTICES.md`). The CSP's `font-src 'self'` covers them; `static` registers the `font/woff2` MIME type. `font-display: swap` with a system-font fallback.

## Static assets and cache busting

`internal/portal/static` embeds the assets; the portal serves them under `/static/` with `Cache-Control: public, max-age=86400`. Templates link assets with `{{asset "portal.css"}}`, which renders `/static/portal.css?v=<first 12 hex of the file's SHA-256>`. A deploy that changes a file changes its URL, so browsers fetch the new copy straight away. An unknown asset name is a template error, not a dead link. Fonts are loaded by `portal.css` with relative URLs (`fonts/…`); `TestFontsReferencedByTheStylesheetAreEmbedded` checks they exist.

## Public pages (no sign-in)

The gateway is a public service, so a few pages answer anonymous visitors with `200` (Google OAuth verification, the Slack Marketplace and the GitHub Marketplace require a homepage, a privacy policy, terms and a support contact reachable without signing in and without a redirect):

| Route | Template | Signed-in user |
|---|---|---|
| `GET /` | `home.html`: what the gateway does, what it does with data (with the Google Limited Use statement), how to sign in (provider names), contact | `303` to `/account`, as before |
| `GET /privacy` | `privacy.html` (DRAFT privacy policy) | same page with the user's nav |
| `GET /terms` | `terms.html` (DRAFT terms of service) | same page with the user's nav |
| `GET /support` | `support.html` (contact, first-aid answers, security reports) | same page with the user's nav |

- The texts are embedded templates (`internal/portal/templates`), no external fetches; operator values come from `portal.Legal` (`portal.LegalFromEnv`, the `GATEWAY_LEGAL_*` variables, see `docs/deploy.md` and `docs/public-launch.md`) and are HTML-escaped; unset ones render as `[operator name]`-style placeholders and are logged at startup (`Legal.Placeholders`).
- `GATEWAY_LEGAL_DRAFT` (default `true`) shows the `Draft – pending review` notice (`<p class="notice draft" role="note" data-legal-draft>`) on `/privacy` and `/terms`.
- Caching: anonymous copies `Cache-Control: public, max-age=300`, signed-in copies `no-store` (the nav carries the CSRF token), always `Vary: Cookie`. The usual hardening headers and CSP apply.
- The sign-in page and the OAuth consent page reference the terms and privacy policy next to the decision.
- Tests: `internal/portal/legal_test.go` (routes, headers, config values, escaping, placeholders, draft marker on/off, sign-in and footer links), `internal/authserver/shell_test.go` (consent links).
