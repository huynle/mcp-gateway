package clientinstall

import "testing"

func TestCommandsUseTheGatewayAddress(t *testing.T) {
	got := Commands("https://gateway.example.com/")
	if len(got) != 3 {
		t.Fatalf("commands = %d, want 3", len(got))
	}
	if want := "curl -fsSL https://gateway.example.com/install | sh"; got[0].Command != want {
		t.Errorf("curl = %q, want %q", got[0].Command, want)
	}
	if got[0].Tab != "curl" || got[1].Command != BrewCommand || got[2].Command != GoCommand {
		t.Errorf("commands = %+v", got)
	}
}

func TestCommandsWithoutBaseURLUseGitHub(t *testing.T) {
	if want := "curl -fsSL " + InstallScriptURL + " | sh"; Commands("")[0].Command != want {
		t.Errorf("curl = %q, want %q", Commands("")[0].Command, want)
	}
}
