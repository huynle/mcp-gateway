# Public launch checklist: homepage, privacy policy, terms

The gateway serves the public pages that Google OAuth verification, the Slack Marketplace and the GitHub Marketplace ask for: `/` (homepage), `/privacy`, `/terms` and `/support`, all reachable without signing in. The legal texts are **drafts generated from what the code does**; they are not legal advice. Before you submit an app for review or open sign-up to the public, work through this list. Implementation notes: [`portal-ui.md`](portal-ui.md#public-pages-no-sign-in).

## 1. Fill in the operator values

| Variable | Shown as when unset | Fill in |
|---|---|---|
| `GATEWAY_LEGAL_OPERATOR_NAME` | `[operator name]` | Legal name of the person or organisation running the gateway (the data controller). |
| `GATEWAY_LEGAL_CONTACT_EMAIL` | `[contact email]` | A monitored bare address for privacy, support and security requests. Slack expects support answers within 2 business days and support that needs no extra account. |
| `GATEWAY_LEGAL_JURISDICTION` | `[jurisdiction]` | Governing law and courts for the terms, e.g. `the State of Washington, USA`. |
| `GATEWAY_LEGAL_EFFECTIVE_DATE` | `[effective date]` | `YYYY-MM-DD` the reviewed texts take effect; change it with every text change. |
| `GATEWAY_LEGAL_DRAFT` | `true` (marker shown) | Set `false` only after step 2. |

The gateway logs `public legal pages show placeholders or the draft marker` at startup until all four values are set and the draft marker is off. Invalid values fail startup. With the Helm chart, set them through `extraEnv` ([`deploy.md`](deploy.md#values)).

## 2. Have the texts reviewed

Texts: `internal/portal/templates/privacy.html`, `terms.html`, `home.html`, `support.html`. Ask counsel to review and adapt at least:

- [ ] Legal bases, data-subject rights and response times for your users' jurisdictions (GDPR/UK GDPR, CCPA/CPRA, ...); whether you need a representative, a DPO, or a DPA with business customers.
- [ ] The minimum age (draft: 16).
- [ ] Liability, warranty and governing-law clauses of the terms.
- [ ] **Audit retention**: the privacy policy promises "up to one year, then deleted". The purge job does not exist yet (Brain task `mjdzepbx`, [`runbooks/audit-export.md`](runbooks/audit-export.md)). Land it, or change the text, before launch.
- [ ] **Log retention**: name the actual retention of your log storage.
- [ ] **Export and deletion**: the policy says users can export or delete their account from My account. Confirm the self-service feature has shipped (public-account work) before launch, or reword.
- [ ] **Subprocessors**: the draft says everything runs on the operator's own infrastructure. If the database, OpenBao/Vault, logs, backups or e-mail run at a cloud provider, list them.
- [ ] Every connector you enable: the Google section lists example scopes. Make it match the scopes your Google, Microsoft, GitHub, Slack and Atlassian apps really request.

When the review is done, apply the edits to the templates, set the effective date and `GATEWAY_LEGAL_DRAFT=false`.

## 3. Route and verify the pages

- [ ] The Ingress routes `/`, `/privacy`, `/terms`, `/support` and `/static` (the chart's default path list does not include the three new pages yet, see [`deploy.md`](deploy.md#public-paths)).
- [ ] From a private browser window: `https://<base>/`, `/privacy`, `/terms`, `/support` answer `200` without a redirect, show no placeholder and no draft marker.
- [ ] The homepage is on a domain you own and have verified in Google Search Console (Google rejects homepages on third-party hosts and homepages that redirect).

## 4. Register the URLs

| Listing | Field | URL |
|---|---|---|
| Google Cloud OAuth consent screen (Branding) | Application home page / privacy policy / terms of service | `<base>/`, `<base>/privacy`, `<base>/terms`; authorised domain = the base URL's domain |
| Slack app (Marketplace submission) | Landing page / privacy policy / support | `<base>/`, `<base>/privacy`, `<base>/support` |
| GitHub App / Marketplace listing | Homepage / privacy policy / terms of service / support | `<base>/`, `<base>/privacy`, `<base>/terms`, `<base>/support` |

Google's verification also needs the scope justifications and, for restricted scopes (e.g. Gmail, Drive), a security assessment; the Limited Use statement is already on the homepage and in the privacy policy.

## 5. After launch

- [ ] Each text change: new effective date, and a portal notice for material changes (the privacy policy promises one).
- [ ] Keep the contact address monitored. A broken privacy or support link gets a Slack Marketplace app delisted.
