package connections

import "net/url"

// FlowErrorMessageForTest exposes the connections page's flow error text.
func FlowErrorMessageForTest(q url.Values) string { return flowErrorText(q) }
