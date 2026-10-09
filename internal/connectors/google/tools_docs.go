package google

import (
	"strings"

	"google.golang.org/api/docs/v1"
)

// DocumentText renders a Docs API document's body as plain text (what
// docs.get_text returns): paragraphs keep their trailing newline,
// bulleted paragraphs get a "- " prefix indented two spaces per nesting
// level, person chips render their name (else their email), rich links
// their title (else their URI), footnote references, page breaks and
// section breaks vanish, tables render one row per line with the cells
// separated by tabs (a cell's paragraphs joined by a space) and tables
// of contents render their entries. Only the body is rendered: headers,
// footers, footnotes and further tabs are left out.
func DocumentText(doc *docs.Document) string {
	if doc == nil || doc.Body == nil {
		return ""
	}
	var b strings.Builder
	writeStructuralElements(&b, doc.Body.Content)
	return b.String()
}

func writeStructuralElements(b *strings.Builder, content []*docs.StructuralElement) {
	for _, el := range content {
		if el == nil {
			continue
		}
		switch {
		case el.Paragraph != nil:
			writeParagraph(b, el.Paragraph)
		case el.Table != nil:
			writeTable(b, el.Table)
		case el.TableOfContents != nil:
			writeStructuralElements(b, el.TableOfContents.Content)
		}
	}
}

func writeParagraph(b *strings.Builder, p *docs.Paragraph) {
	if p.Bullet != nil {
		b.WriteString(strings.Repeat("  ", int(p.Bullet.NestingLevel)))
		b.WriteString("- ")
	}
	for _, pe := range p.Elements {
		if pe == nil {
			continue
		}
		switch {
		case pe.TextRun != nil:
			b.WriteString(pe.TextRun.Content)
		case pe.Person != nil && pe.Person.PersonProperties != nil:
			if pe.Person.PersonProperties.Name != "" {
				b.WriteString(pe.Person.PersonProperties.Name)
			} else {
				b.WriteString(pe.Person.PersonProperties.Email)
			}
		case pe.RichLink != nil && pe.RichLink.RichLinkProperties != nil:
			if pe.RichLink.RichLinkProperties.Title != "" {
				b.WriteString(pe.RichLink.RichLinkProperties.Title)
			} else {
				b.WriteString(pe.RichLink.RichLinkProperties.Uri)
			}
		}
	}
}

func writeTable(b *strings.Builder, t *docs.Table) {
	for _, row := range t.TableRows {
		if row == nil {
			continue
		}
		for i, cell := range row.TableCells {
			if i > 0 {
				b.WriteByte('\t')
			}
			if cell == nil {
				continue
			}
			var cb strings.Builder
			writeStructuralElements(&cb, cell.Content)
			b.WriteString(strings.Join(strings.Fields(cb.String()), " "))
		}
		b.WriteByte('\n')
	}
}
