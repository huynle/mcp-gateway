package elicit_test

import (
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/federation/elicit"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// Both features are off unless their variable says otherwise.
func TestConfigFromEnvDefaultsOff(t *testing.T) {
	cfg, err := elicit.ConfigFromEnv(env(nil))
	if err != nil || cfg.CredentialLinks || cfg.UpstreamElicitation {
		t.Errorf("ConfigFromEnv(empty) = %+v, %v; want both off", cfg, err)
	}
	cfg, err = elicit.ConfigFromEnv(env(map[string]string{elicit.EnvCredentialLinks: "  ", elicit.EnvUpstreamElicitation: ""}))
	if err != nil || cfg.CredentialLinks || cfg.UpstreamElicitation {
		t.Errorf("ConfigFromEnv(blank) = %+v, %v; want both off", cfg, err)
	}
}

// Each variable turns on only its own feature; strconv.ParseBool values.
func TestConfigFromEnvReadsEachFlag(t *testing.T) {
	cases := []struct {
		links, relay string
		want         elicit.Config
	}{
		{"true", "", elicit.Config{CredentialLinks: true}},
		{"", "1", elicit.Config{UpstreamElicitation: true}},
		{" TRUE ", "t", elicit.Config{CredentialLinks: true, UpstreamElicitation: true}},
		{"false", "0", elicit.Config{}},
	}
	for _, tc := range cases {
		got, err := elicit.ConfigFromEnv(env(map[string]string{elicit.EnvCredentialLinks: tc.links, elicit.EnvUpstreamElicitation: tc.relay}))
		if err != nil || got != tc.want {
			t.Errorf("ConfigFromEnv(%q, %q) = %+v, %v; want %+v", tc.links, tc.relay, got, err, tc.want)
		}
	}
}

// An unparsable value is a startup error naming the variable, never a
// silent default.
func TestConfigFromEnvRejectsBadValues(t *testing.T) {
	for _, name := range []string{elicit.EnvCredentialLinks, elicit.EnvUpstreamElicitation} {
		cfg, err := elicit.ConfigFromEnv(env(map[string]string{name: "yes please"}))
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s=yes please: err = %v, want an error naming %s", name, err, name)
		}
		if cfg != (elicit.Config{}) {
			t.Errorf("%s=yes please: cfg = %+v, want zero", name, cfg)
		}
	}
}

func TestEnvNames(t *testing.T) {
	if elicit.EnvCredentialLinks != "GATEWAY_CREDENTIAL_LINKS_ENABLED" || elicit.EnvUpstreamElicitation != "GATEWAY_UPSTREAM_ELICITATION_ENABLED" {
		t.Errorf("env names = %s, %s", elicit.EnvCredentialLinks, elicit.EnvUpstreamElicitation)
	}
}
