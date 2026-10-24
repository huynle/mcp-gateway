{{/*
Chart name, release-qualified name and labels.
*/}}
{{- define "mcp-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "mcp-gateway.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "mcp-gateway.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "mcp-gateway.labels" -}}
helm.sh/chart: {{ include "mcp-gateway.chart" . }}
{{ include "mcp-gateway.selectorLabels" . }}
app.kubernetes.io/version: {{ include "mcp-gateway.imageTag" . | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "mcp-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mcp-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "mcp-gateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "mcp-gateway.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "mcp-gateway.imageTag" -}}
{{- default .Chart.AppVersion .Values.image.tag }}
{{- end }}

{{- define "mcp-gateway.image" -}}
{{- printf "%s:%s" .Values.image.repository (include "mcp-gateway.imageTag" .) }}
{{- end }}

{{/*
Render-time invariants. Called from the Deployment so every render runs them.
*/}}
{{- define "mcp-gateway.validate" -}}
{{- if lt (int .Values.replicaCount) 2 }}
{{- fail (printf "replicaCount must be at least 2 (got %v): the gateway runs as identical stateless replicas behind the Service (decision ysorv868)" .Values.replicaCount) }}
{{- end }}
{{- if not (has .Values.keyProvider.type (list "vault" "file")) }}
{{- fail (printf "keyProvider.type must be vault or file (got %q)" .Values.keyProvider.type) }}
{{- end }}
{{- if not (hasPrefix "http" .Values.gateway.baseURL) }}
{{- fail (printf "gateway.baseURL must be an absolute URL (got %q)" .Values.gateway.baseURL) }}
{{- end }}
{{- if hasSuffix "/" .Values.gateway.baseURL }}
{{- fail "gateway.baseURL must not end with a slash" }}
{{- end }}
{{- if .Values.tunnelRelay.enabled }}
{{- if not .Values.tunnelRelay.existingSecret }}
{{- fail "tunnelRelay.existingSecret is required when tunnelRelay.enabled (the GATEWAY_RELAY_SECRET shared by every replica)" }}
{{- end }}
{{- if has (int .Values.tunnelRelay.port) (list (int .Values.gateway.httpPort) (int .Values.gateway.metricsPort)) }}
{{- fail "tunnelRelay.port must differ from gateway.httpPort and gateway.metricsPort" }}
{{- end }}
{{- end }}
{{- range .Values.oidc.providers }}
{{- if not (regexMatch "^[a-z0-9-]+$" .name) }}
{{- fail (printf "oidc.providers[].name %q: lower-case letters, digits and hyphens only" .name) }}
{{- end }}
{{- if and (not .allowedDomains) (not .allowedTenants) }}
{{- fail (printf "oidc provider %q needs allowedDomains and/or allowedTenants" .name) }}
{{- end }}
{{- if not .clientSecret.secretName }}
{{- fail (printf "oidc provider %q needs clientSecret.secretName" .name) }}
{{- end }}
{{- end }}
{{- end }}

{{/*
terminationGracePeriodSeconds: explicit value or drain + 10 s.
*/}}
{{- define "mcp-gateway.terminationGracePeriodSeconds" -}}
{{- if .Values.gateway.terminationGracePeriodSeconds }}
{{- int .Values.gateway.terminationGracePeriodSeconds }}
{{- else }}
{{- add (int .Values.gateway.drainTimeoutSeconds) 10 }}
{{- end }}
{{- end }}

{{/*
Ingress host: explicit or the host of baseURL.
*/}}
{{- define "mcp-gateway.ingressHost" -}}
{{- if .Values.ingress.host }}
{{- .Values.ingress.host }}
{{- else }}
{{- (urlParse .Values.gateway.baseURL).host }}
{{- end }}
{{- end }}

{{/*
Environment variable name fragment for an OIDC provider name.
*/}}
{{- define "mcp-gateway.oidcEnvName" -}}
{{- . | replace "-" "_" | upper }}
{{- end }}

{{/*
Key file path for the file provider.
*/}}
{{- define "mcp-gateway.keyFilePath" -}}
{{- printf "%s/%s" (.Values.keyProvider.file.mountPath | trimSuffix "/") .Values.keyProvider.file.secretKey }}
{{- end }}

{{/*
The gateway container's environment (shared by nothing else; the migrate
Job has its own, smaller, set).
*/}}
{{- define "mcp-gateway.env" -}}
{{- $g := .Values.gateway }}
- name: GATEWAY_LISTEN_ADDR
  value: {{ printf ":%d" (int $g.httpPort) | quote }}
- name: GATEWAY_METRICS_ADDR
  value: {{ printf "0.0.0.0:%d" (int $g.metricsPort) | quote }}
- name: GATEWAY_DRAIN_TIMEOUT
  value: {{ printf "%ds" (int $g.drainTimeoutSeconds) | quote }}
{{- if .Values.tunnelRelay.enabled }}
{{- $r := .Values.tunnelRelay }}
- name: POD_IP
  valueFrom:
    fieldRef:
      fieldPath: status.podIP
- name: GATEWAY_RELAY_LISTEN_ADDR
  value: {{ printf ":%d" (int $r.port) | quote }}
- name: GATEWAY_RELAY_ADVERTISE_ADDR
  value: {{ printf "http://$(POD_IP):%d" (int $r.port) | quote }}
- name: GATEWAY_RELAY_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ $r.existingSecret | quote }}
      key: {{ $r.secretKey | quote }}
{{- end }}
- name: GATEWAY_LOG_LEVEL
  value: {{ $g.logLevel | quote }}
- name: GATEWAY_LOG_FORMAT
  value: {{ $g.logFormat | quote }}
- name: GATEWAY_BASE_URL
  value: {{ $g.baseURL | quote }}
- name: GATEWAY_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.database.existingSecret | quote }}
      key: {{ .Values.database.appURLKey | quote }}
- name: GATEWAY_JOBS_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.database.existingSecret | quote }}
      key: {{ .Values.database.jobsURLKey | quote }}
- name: GATEWAY_SESSION_IDLE_TIMEOUT
  value: {{ $g.session.idleTimeout | quote }}
- name: GATEWAY_SESSION_ABSOLUTE_TIMEOUT
  value: {{ $g.session.absoluteTimeout | quote }}
- name: GATEWAY_SESSION_COOKIE_SECURE
  value: {{ $g.session.cookieSecure | quote }}
- name: GATEWAY_TOKEN_SIGNIN_MAX_AGE
  value: {{ $g.tokens.signinMaxAge | quote }}
- name: GATEWAY_MCP_MAX_BODY
  value: {{ int64 $g.mcp.maxBody | quote }}
- name: GATEWAY_RATE_USER_PER_MIN
  value: {{ int64 $g.rateLimits.userPerMinute | quote }}
- name: GATEWAY_RATE_APP_PER_MIN
  value: {{ int64 $g.rateLimits.appPerMinute | quote }}
- name: GATEWAY_POLICY_RELOAD_INTERVAL
  value: {{ $g.policy.reloadInterval | quote }}
- name: GATEWAY_APPROVAL_TTL
  value: {{ $g.approvals.ttl | quote }}
- name: GATEWAY_APPROVAL_WAIT
  value: {{ $g.approvals.wait | quote }}
- name: GATEWAY_LEDGER_IDEMPOTENCY_WINDOW
  value: {{ $g.ledger.idempotencyWindow | quote }}
- name: GATEWAY_LEDGER_STALE_AFTER
  value: {{ $g.ledger.staleAfter | quote }}
- name: GATEWAY_LEDGER_MAX_RECONCILE_ATTEMPTS
  value: {{ int64 $g.ledger.maxReconcileAttempts | quote }}
- name: GATEWAY_LEDGER_MAX_RECONCILE_AGE
  value: {{ $g.ledger.maxReconcileAge | quote }}
- name: GATEWAY_OAUTH_ACCESS_TOKEN_TTL
  value: {{ $g.oauth.accessTokenTTL | quote }}
- name: GATEWAY_OAUTH_REFRESH_TOKEN_TTL
  value: {{ $g.oauth.refreshTokenTTL | quote }}
- name: GATEWAY_OAUTH_CODE_TTL
  value: {{ $g.oauth.codeTTL | quote }}
- name: GATEWAY_OAUTH_REGISTER_PER_MIN
  value: {{ int64 $g.oauth.registerPerMinute | quote }}
- name: GATEWAY_OAUTH_MAX_UNUSED_CLIENTS
  value: {{ int64 $g.oauth.maxUnusedClients | quote }}
- name: GATEWAY_OAUTH_CLIENT_IDLE
  value: {{ $g.oauth.clientIdle | quote }}
- name: GATEWAY_OAUTH_KEY_ROTATION
  value: {{ $g.oauth.keyRotation | quote }}
- name: GATEWAY_OAUTH_KEY_GRACE
  value: {{ $g.oauth.keyGrace | quote }}
- name: GATEWAY_DEFAULT_ROLE
  value: {{ $g.defaultRole | quote }}
{{- if $g.bootstrapAdmins }}
- name: GATEWAY_BOOTSTRAP_ADMINS
  value: {{ join "," $g.bootstrapAdmins | quote }}
{{- end }}
- name: GATEWAY_SECRETS_ENABLED
  value: {{ $g.secrets.enabled | quote }}
- name: GATEWAY_CREDENTIAL_LINKS_ENABLED
  value: {{ $g.credentialLinks.enabled | quote }}
- name: GATEWAY_UPSTREAM_ELICITATION_ENABLED
  value: {{ $g.upstreamElicitation.enabled | quote }}
- name: GATEWAY_ENABLE_FAKE_CONNECTOR
  value: {{ $g.enableFakeConnector | quote }}
{{- if .Values.oidc.providers }}
{{- $names := list }}
{{- range .Values.oidc.providers }}{{ $names = append $names .name }}{{ end }}
- name: GATEWAY_OIDC_PROVIDERS
  value: {{ join "," $names | quote }}
{{- range .Values.oidc.providers }}
{{- $n := include "mcp-gateway.oidcEnvName" .name }}
{{- if .displayName }}
- name: GATEWAY_OIDC_{{ $n }}_DISPLAY_NAME
  value: {{ .displayName | quote }}
{{- end }}
- name: GATEWAY_OIDC_{{ $n }}_ISSUER
  value: {{ required (printf "oidc provider %q needs issuer" .name) .issuer | quote }}
- name: GATEWAY_OIDC_{{ $n }}_CLIENT_ID
  value: {{ required (printf "oidc provider %q needs clientID" .name) .clientID | quote }}
- name: GATEWAY_OIDC_{{ $n }}_CLIENT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ .clientSecret.secretName | quote }}
      key: {{ .clientSecret.secretKey | default (printf "%s-client-secret" .name) | quote }}
{{- if .allowedDomains }}
- name: GATEWAY_OIDC_{{ $n }}_ALLOWED_DOMAINS
  value: {{ join "," .allowedDomains | quote }}
{{- end }}
{{- if .allowedTenants }}
- name: GATEWAY_OIDC_{{ $n }}_ALLOWED_TENANTS
  value: {{ join "," .allowedTenants | quote }}
{{- end }}
{{- if .domainClaim }}
- name: GATEWAY_OIDC_{{ $n }}_DOMAIN_CLAIM
  value: {{ .domainClaim | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- if eq .Values.keyProvider.type "vault" }}
- name: GATEWAY_KEY_PROVIDER
  value: "vault"
- name: GATEWAY_VAULT_ADDR
  value: {{ required "keyProvider.vault.addr is required" .Values.keyProvider.vault.addr | quote }}
- name: GATEWAY_VAULT_TRANSIT_KEY
  value: {{ .Values.keyProvider.vault.transitKey | quote }}
- name: GATEWAY_VAULT_MOUNT
  value: {{ .Values.keyProvider.vault.mount | quote }}
- name: GATEWAY_VAULT_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ required "keyProvider.vault.token.existingSecret is required" .Values.keyProvider.vault.token.existingSecret | quote }}
      key: {{ .Values.keyProvider.vault.token.secretKey | quote }}
{{- else }}
- name: GATEWAY_KEY_PROVIDER
  value: "file"
- name: GATEWAY_KEY_FILE
  value: {{ include "mcp-gateway.keyFilePath" . | quote }}
{{- end }}
{{- if .Values.logSalt.existingSecret }}
- name: GATEWAY_LOG_SALT
  valueFrom:
    secretKeyRef:
      name: {{ .Values.logSalt.existingSecret | quote }}
      key: {{ .Values.logSalt.secretKey | quote }}
{{- end }}
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end }}
