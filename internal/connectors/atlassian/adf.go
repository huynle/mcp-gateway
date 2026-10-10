package atlassian

import (
	"encoding/json"
	"strings"
)

// Atlassian Document Format (ADF) is what Jira Cloud's v3 API takes and
// returns for rich text (descriptions, comments). The connector needs
// only two things of it: building a document from plain text (one
// paragraph per line, plus the marker paragraph) and reading the text
// back out of any document (to show a description and to find a marker).

// adfNode is the minimal ADF node: a type, an optional text and children.
type adfNode struct {
	Type    string    `json:"type"`
	Version int       `json:"version,omitempty"`
	Text    string    `json:"text,omitempty"`
	Content []adfNode `json:"content,omitempty"`
}

// adfParagraph builds a paragraph with one text node (an empty paragraph
// when text is empty).
func adfParagraph(text string) adfNode {
	p := adfNode{Type: "paragraph"}
	if text != "" {
		p.Content = []adfNode{{Type: "text", Text: text}}
	}
	return p
}

// adfDocument builds a document from plain text (one paragraph per
// non-empty line; blank lines are dropped) followed by extra paragraphs
// (the marker). An empty text with no extras gives a document with one
// empty paragraph, which Jira accepts.
func adfDocument(text string, extra ...string) adfNode {
	doc := adfNode{Type: "doc", Version: 1}
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if line = strings.TrimRight(line, " \t"); line != "" {
			doc.Content = append(doc.Content, adfParagraph(line))
		}
	}
	for _, e := range extra {
		doc.Content = append(doc.Content, adfParagraph(e))
	}
	if len(doc.Content) == 0 {
		doc.Content = []adfNode{adfParagraph("")}
	}
	return doc
}

// adfText extracts the plain text of an ADF document (raw JSON as Jira
// returns it): text nodes concatenated, block nodes separated by
// newlines, hard breaks as newlines. A null or empty value is "". A
// value that is a plain string (Jira v2 style) is returned as is.
func adfText(raw json.RawMessage) string {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return s
		}
		return ""
	}
	var node adfNode
	if err := json.Unmarshal(raw, &node); err != nil {
		return ""
	}
	var b strings.Builder
	walkADF(&b, node)
	return strings.TrimRight(b.String(), "\n")
}

// walkADF appends the node's text to b.
func walkADF(b *strings.Builder, n adfNode) {
	switch n.Type {
	case "text":
		b.WriteString(n.Text)
		return
	case "hardBreak":
		b.WriteByte('\n')
		return
	case "mention", "emoji", "inlineCard", "date", "status":
		// Inline atoms carry their label in attributes the minimal node
		// does not keep; the text around them is what matters.
		return
	}
	for _, c := range n.Content {
		walkADF(b, c)
	}
	if isADFBlock(n.Type) {
		b.WriteByte('\n')
	}
}

// isADFBlock reports whether the node type is a leaf block that ends a
// line. Containers (lists, list items, quotes, panels, tables) hold
// paragraphs, which end their own lines, so they add none.
func isADFBlock(t string) bool {
	switch t {
	case "paragraph", "heading", "codeBlock", "rule":
		return true
	}
	return false
}
