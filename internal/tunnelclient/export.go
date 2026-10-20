package tunnelclient

// SplitCommand splits a command line into arguments exactly like --stdio:
// whitespace separates, single quotes are literal, double quotes allow \"
// and \\, a backslash outside quotes escapes the next character. No shell
// expansion of any kind happens. Shared with internal/machineclient
// (config.yaml `stdio:`).
func SplitCommand(s string) ([]string, error) { return splitCommand(s) }
