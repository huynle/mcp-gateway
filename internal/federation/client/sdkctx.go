package client

import (
	"context"
	"reflect"
	"strings"
)

// sdkPkgPrefix is the import path prefix of the MCP go-sdk packages.
const sdkPkgPrefix = "github.com/modelcontextprotocol/go-sdk/"

// withoutSDKValues hides the go-sdk's own context values from the SDK
// client we drive.
//
// The gateway calls Connect and the operations from inside its own go-sdk
// MCP server handler, so the context carries values the SDK's server side
// stored for the inbound request. The SDK uses the same keys on both
// sides: its client transport sets the Mcp-Protocol-Version header from the
// context when it has nothing better (go-sdk v1.8.0 setMCPHeaders), so the
// downstream client's version (e.g. 2026-07-28) ended up on our initialize
// to the upstream, and a stateful upstream rejected it (quirk 91d7smmg).
// Values with other keys (deadlines, tracing, the gateway's own) pass
// through; cancellation and deadlines are untouched.
func withoutSDKValues(ctx context.Context) context.Context {
	return sdkFreeCtx{ctx}
}

type sdkFreeCtx struct{ context.Context }

func (c sdkFreeCtx) Value(key any) any {
	if isSDKKey(key) {
		return nil
	}
	return c.Context.Value(key)
}

// isSDKKey reports whether key's type (through pointers) is declared in a
// go-sdk package.
func isSDKKey(key any) bool {
	t := reflect.TypeOf(key)
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t != nil && strings.HasPrefix(t.PkgPath(), sdkPkgPrefix)
}
