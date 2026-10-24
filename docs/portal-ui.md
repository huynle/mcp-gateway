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

- `page.head`: meta tags (viewport with `viewport-fit=cover`), `theme.js` (render-blocking, so a stored theme is applied before the first paint), `portal.css`, `htmx.min.js` (deferred), and the installable-app tags: the manifest link, `theme-color` (light/dark), the iOS home-screen tags and `pwa.js` (deferred). See "Installable app (PWA)".
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

## Installable app (PWA)

The portal can be installed as an app (home screen / dock) so approvals are one tap away, and is ready for Web Push (decision 0pzhidap). Everything is same-origin, so the CSP is unchanged (`default-src 'self'` covers the manifest and the worker).

| Route | What | Caching |
|---|---|---|
| `GET /manifest.webmanifest` | `application/manifest+json`, built from a Go struct (`internal/portal/pwa.go`): name "MCP Gateway", short name "Gateway", `id` and `scope` `/`, `start_url` `/approvals`, `display: standalone`, background `#f6f7f9`, theme `#0e7268`; icons 192 and 512 (`any`) and 512 `maskable`, by their versioned `/static/…?v=` URLs | `public, max-age=3600` |
| `GET /sw.js` | the service worker, at the root so its scope is `/`. Source: `internal/portal/static/sw.js` (embedded as `static.ServiceWorker`, **not** served under `/static/`); at start-up the portal fills its three placeholders (`"__CACHE_VERSION__"`, `["__PRECACHE_URLS__"]`, `"__ICON_URL__"`) with JSON values, so the served bytes are fixed per build | `no-cache` (browsers revalidate on every update check) |
| `GET /offline` | `offline.html` on the shared shell: "You're offline" with a Retry link (`href=""`: reloads the address in the bar, since the worker shows this page in place of the page that failed) | `public, max-age=300` |

All three are public (no sign-in) and carry the usual hardening headers. `/offline` is **always rendered anonymously** (no user nav, no CSRF token), even for a signed-in request, because the worker caches it. The chart's ingress routes the three paths (`deploy/helm/mcp-gateway/values.yaml`).

Service worker rules (`sw.js`):

- **install**: precache, in the cache `mcp-gateway-static-<version>`, only the static assets by their versioned URLs (`portal.css`, `theme.js`, `htmx.min.js`, `copy.js`, `pwa.js`, `favicon.svg`, every `fonts/*.woff2` and `icons/*.png`) and `/offline` (fetched with `credentials: "omit"`). The version is the first 12 hex digits of a SHA-256 over the worker source, the URL list, `nav.Partial` and the offline page's templates, so any change to them installs a fresh cache. Then `skipWaiting()`.
- **activate**: delete the other `mcp-gateway-*` caches, `clients.claim()`.
- **fetch**: non-GET requests are not intercepted. Navigations are **network only**; on a network error the cached `/offline` page. Same-origin `GET /static/…` is cache first (a miss is fetched and stored when it is a plain 200). Anything else (htmx requests, `/mcp`, other origins) is not intercepted. Page HTML, signed in or not, is never stored.
- **push**: `event.data.json()` as `{title, body, url, tag}` → `showNotification(title, {body, tag, renotify: true, icon, badge, data: {url}})` (`renotify` only with a tag: browsers reject it without one). A missing or invalid payload shows "MCP Gateway" / "Something needs your attention" for `/approvals`.
- **notificationclick**: closes the notification and opens `data.url` only if it is a same-origin path (`/…`, not `//…`); anything else opens `/approvals`. An open window showing that URL is focused; otherwise an open portal window is focused and navigated; otherwise a new window opens.

`pwa.js` registers `/sw.js` with `{scope: "/"}` when `"serviceWorker" in navigator` and the page is a secure context (HTTPS or localhost), and does nothing else. Its `onRegistered(registration)` function is the hook for the "notifications on this device" control (`data-push-*` elements, `registration.pushManager`).

**Icons** live in `internal/portal/static/icons/`: `icon-192.png`, `icon-512.png` (the favicon's rounded square, transparent corners), `icon-maskable-512.png` (full-bleed teal, the arch inside the 80% safe zone) and `apple-touch-icon.png` (180×180, opaque; iOS rounds it and shows transparency as black). They are rendered from the brand mark (`favicon.svg`) by `python3 scripts/render-pwa-icons.py` (Playwright + Chromium, Pillow; deterministic: a re-run without SVG changes leaves the files byte-identical). Commit the PNGs; the binary embeds them.

**Safe areas**: the viewport is `viewport-fit=cover`, so an installed app draws under the notch and the home indicator. `portal.css` pads the top bar (top, left, right), the sidebar/drawer (top, bottom), `main` (left, right) and the footer (bottom) by `env(safe-area-inset-*)`, which is 0 elsewhere.

**Installing**:

- Android (Chrome, Edge, Samsung Internet): open the gateway over HTTPS, then the browser menu → *Install app* (or the install prompt in the address bar). Desktop Chrome/Edge: the install icon in the address bar.
- iOS / iPadOS (Safari 16.4+): Share → *Add to Home Screen*. Web Push on iOS works only from the installed app.

Tests: `internal/portal/pwa_test.go` (manifest fields and icon sizes, worker headers, precache URLs all resolve, no navigation caching, `node --check` of the served worker and `pwa.js` when node is installed, the offline page is anonymous and on the shell, hardening headers), `internal/portal/static/static_test.go` (icons embedded, sizes, opacity; the worker source is not a `/static/` asset), `internal/portal/nav/nav_test.go` (the head tags).
