// Package webpush sends Web Push notifications to browser subscriptions
// using only the standard library:
//
//   - RFC 8030 (Generic Event Delivery Using HTTP Push): one POST per
//     message to the subscription's endpoint, with TTL, Urgency and
//     optional Topic headers;
//   - RFC 8291 (Message Encryption for Web Push) over RFC 8188
//     ("aes128gcm" content coding): an ephemeral P-256 ECDH key per
//     message, HKDF-SHA256 key derivation bound to the subscription's auth
//     secret, a single AES-128-GCM record of at most 4096 octets;
//   - RFC 8292 (VAPID): every request carries
//     "Authorization: vapid t=<ES256 JWT>, k=<public key>" so the push
//     service can tie the subscription to this application server.
//
// # Threat model
//
// A subscription, and therefore its endpoint URL, is supplied by a browser
// the gateway does not control. Sending to it is an outbound request to a
// user-chosen URL, i.e. an SSRF vector. Two independent layers stop that:
//
//  1. ValidateEndpoint (run by ParseSubscription when a subscription is
//     stored, and again by Sender.Send before every request) accepts only
//     https URLs on port 443 whose host is a known push service
//     (DefaultAllowedHosts, or a subdomain of DefaultAllowedSuffixes).
//  2. The HTTP client should be the netguard SSRF-safe client
//     (NewGuardedClient, also the default when Options.Client is nil), which
//     refuses internal addresses at dial time even if a push-service name
//     were ever made to resolve to one. Redirects are never followed.
//
// The endpoint URL is a bearer capability: anyone who knows it can push to
// that browser. Errors from this package name the endpoint's host only,
// never its path or query, and callers must not log the URL either.
//
// # Payload content
//
// Push services see message metadata, and the payload sits on the user's
// device outside the gateway's control. Payloads must stay minimal (an
// opaque identifier and a generic title) and must never contain approval
// arguments, tool inputs, secrets or other sensitive data; the client
// fetches details over the authenticated portal API instead.
//
// Design: Brain decision 0pzhidap.
package webpush
