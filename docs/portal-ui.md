# Portal UI: shared shell, styles and theme

Every portal page (packages `portal`, `tokens`, `approvals`, `ledger`, `connections`, `authserver`, `policy`, `audit`, `federation/portal`, `federation/admin`) is built on one shell owned by `internal/portal/nav`. Modules keep their own templates (decisions 7datr7x4, u46t7kmq); they share the head, the nav bar and one stylesheet.

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
<h1>{{.Title}}</h1>
{{end}}
```

Parse the template set with `nav.Setup(template.New(""))` (it registers `navData`, the `asset` function and the partials) and render with `nav.Execute`.

- `page.head`: meta tags, `theme.js` (render-blocking, so a stored theme is applied before the first paint), `portal.css`, `htmx.min.js` (deferred).
- `nav`: brand, user and admin links (`nav.UserLinks`, `nav.AdminLinks`), the theme toggle and sign-out.
- `footer`: links to the public Privacy Policy, Terms of Service and Support pages; layouts render `{{template "footer"}}` after `</main>`. The portal's layout and the authserver's (consent, harnesses) do; other modules' layouts can adopt it with that one line.
- No `<style>` blocks or `style=` attributes in templates: rules go into `internal/portal/static/portal.css`, page-specific sheets (like `review.css`) next to it.

Drift is caught by tests: `navtest.AssertShell` (called from each module's `shell_test.go`) checks a rendered page links the shared stylesheet and theme script and has the toggle and `<main>`; `TestEveryLayoutUsesTheSharedHead` (internal/portal) scans every `templates/*.html` under `internal/`.

## Static assets and cache busting

`internal/portal/static` embeds the assets; the portal serves them under `/static/` with `Cache-Control: public, max-age=86400`. Templates link assets with `{{asset "portal.css"}}`, which renders `/static/portal.css?v=<first 12 hex of the file's SHA-256>`. A deploy that changes a file changes its URL, so browsers fetch the new copy straight away. An unknown asset name is a template error, not a dead link.

## Theme: light, dark, system

- Colours are CSS custom properties (`--bg`, `--surface`, `--fg`, `--muted`, `--line`, `--input-border`, `--accent`, `--accent-fg`, `--danger`, `--danger-fg`, `--ok`, `--warn`, `--focus`).
- `:root` is the light palette, `:root[data-theme="dark"]` the dark one, and `@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) }` repeats the dark palette for the system setting.
- `theme.js` reads `localStorage["mcp-gateway-theme"]` (`light` or `dark`; absent = system) and sets or removes `<html data-theme>`. The toggle is three buttons (`data-theme-choice`, `aria-pressed`) in a labelled group (`role="group"`, `aria-label="Color theme"`), rendered `hidden` and revealed by the script. A change in another tab is followed through the `storage` event.
- Without JavaScript the toggle stays hidden and the page follows the system setting.
- `palette_test.go` checks that both palettes define the same variables, that the system copy equals the dark palette, and WCAG AA contrast: 4.5:1 for text and status colours on `--bg` and `--surface` and for button labels, 3:1 for input borders and the focus ring.

## Wide tables

Wrap a wide table in `<div class="table-scroll">`; it scrolls inside its box, so the page never overflows. Use `.mono`, `.clip` (one line, ellipsis) and `ul.ids` for identifiers, and always put the full value in `title`. Below 60rem every other table in `<main>` scrolls horizontally on its own.

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
- Prose styles: `.legal` (readable width) and `.site-footer` in `portal.css`.
- Tests: `internal/portal/legal_test.go` (routes, headers, config values, escaping, placeholders, draft marker on/off, sign-in and footer links), `internal/authserver/shell_test.go` (consent links).
