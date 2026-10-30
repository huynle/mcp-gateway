package google

import (
	"context"
	"sort"
	"strings"

	"google.golang.org/api/forms/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Forms tool names (increment 4; the app is read only).
const (
	ToolGetForm       = "get"
	ToolListResponses = "list_responses"
)

// formOtherOption is how an "Other" choice (free text) is listed.
const formOtherOption = "(other)"

// FormRow is one row of a grid question (its own question id).
type FormRow struct {
	QuestionID string `json:"question_id"`
	Title      string `json:"title"`
}

// FormItem is one item of a form: a question, a grid, or a layout item
// (page_break, text_block, image, video).
type FormItem struct {
	ItemID     string    `json:"item_id"`
	Title      string    `json:"title,omitempty"`
	Type       string    `json:"type"`
	QuestionID string    `json:"question_id,omitempty"`
	Required   bool      `json:"required,omitempty"`
	ChoiceType string    `json:"choice_type,omitempty"`
	Options    []string  `json:"options,omitempty"`
	Rows       []FormRow `json:"rows,omitempty"`
}

// FormInfo is forms.get's result.
type FormInfo struct {
	FormID       string     `json:"form_id"`
	Title        string     `json:"title"`
	Description  string     `json:"description,omitempty"`
	ResponderURI string     `json:"responder_uri,omitempty"`
	Items        []FormItem `json:"items"`
	Truncated    bool       `json:"truncated,omitempty"`
}

// FormAnswer is one answered question of a response: the text values,
// or for a file upload the file names (Values) and Drive ids (FileIDs).
type FormAnswer struct {
	QuestionID string   `json:"question_id"`
	Values     []string `json:"values"`
	FileIDs    []string `json:"file_ids,omitempty"`
}

// FormResponseItem is one list_responses item.
type FormResponseItem struct {
	ResponseID        string       `json:"response_id"`
	CreateTime        string       `json:"create_time,omitempty"`
	LastSubmittedTime string       `json:"last_submitted_time,omitempty"`
	RespondentEmail   string       `json:"respondent_email,omitempty"`
	Answers           []FormAnswer `json:"answers"`
	// Truncated says answer values were cut to fit the result bounds.
	Truncated bool `json:"truncated,omitempty"`
}

// FormResponsesPage is list_responses's result.
type FormResponsesPage struct {
	FormID        string             `json:"form_id"`
	MaxResults    int                `json:"max_results"`
	NextPageToken string             `json:"next_page_token,omitempty"`
	HasMore       bool               `json:"has_more"`
	Truncated     bool               `json:"truncated,omitempty"`
	Items         []FormResponseItem `json:"items"`
}

var formIDProperty = property{"form_id", "string", "The form's id (from drive.search, or the id in its edit URL).", nil}

func (c *Connector) formsReadTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppForms, Name: ToolGetForm, Kind: connectors.KindRead,
			Description: "Get a Google Form's structure by id: title, description, responder_uri and its items (item_id, title, type: text, " +
				"paragraph, choice, scale, date, time, rating, file_upload, grid, page_break, text_block, image, video; question_id, required, " +
				"choice_type and options for choices, rows for grids). Use the question ids to read list_responses' answers.",
			InputSchema:      objectSchema([]property{formIDProperty}, []string{"form_id"}),
			RequiredScopes:   []string{ScopeFormsBodyReadonly},
			ResourceIdentity: formIdentity,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppForms, Name: ToolListResponses, Kind: connectors.KindRead,
			Description: "List a Google Form's responses: response_id, create_time, last_submitted_time, respondent_email (when the form " +
				"collects it) and answers (question_id with values; file uploads give file names and Drive file_ids). Question ids come from forms.get.",
			InputSchema: objectSchema([]property{
				formIDProperty,
				{"max_results", "integer", "Responses per page (default 25).", nil},
				{"page_token", "string", "next_page_token of a previous call.", nil},
			}, []string{"form_id"}),
			RequiredScopes:   []string{ScopeFormsResponsesReadonly},
			ResourceIdentity: formIdentity,
			Bounds:           c.pagedBounds(),
		},
	}
}

func (c *Connector) formsReadHandlers() map[string]handler {
	return map[string]handler{ToolGetForm: c.getForm, ToolListResponses: c.listFormResponses}
}

// formIdentity extracts form_id; never answers or titles.
func formIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	if id, _ := args["form_id"].(string); strings.TrimSpace(id) != "" {
		out["form_id"] = strings.TrimSpace(id)
	}
	return out
}

// choiceOptions lists a choice question's option values ("(other)" for
// the free-text option).
func choiceOptions(q *forms.ChoiceQuestion) (string, []string) {
	if q == nil {
		return "", nil
	}
	var out []string
	for _, o := range q.Options {
		switch {
		case o == nil:
		case o.IsOther:
			out = append(out, formOtherOption)
		default:
			out = append(out, o.Value)
		}
	}
	return q.Type, out
}

// questionType names a question's kind.
func questionType(q *forms.Question) string {
	switch {
	case q.ChoiceQuestion != nil:
		return "choice"
	case q.TextQuestion != nil && q.TextQuestion.Paragraph:
		return "paragraph"
	case q.TextQuestion != nil:
		return "text"
	case q.ScaleQuestion != nil:
		return "scale"
	case q.DateQuestion != nil:
		return "date"
	case q.TimeQuestion != nil:
		return "time"
	case q.RatingQuestion != nil:
		return "rating"
	case q.FileUploadQuestion != nil:
		return "file_upload"
	}
	return "question"
}

func toFormItem(it *forms.Item) FormItem {
	out := FormItem{ItemID: it.ItemId, Title: it.Title}
	switch {
	case it.QuestionItem != nil && it.QuestionItem.Question != nil:
		q := it.QuestionItem.Question
		out.Type, out.QuestionID, out.Required = questionType(q), q.QuestionId, q.Required
		out.ChoiceType, out.Options = choiceOptions(q.ChoiceQuestion)
	case it.QuestionGroupItem != nil:
		out.Type = "grid"
		if g := it.QuestionGroupItem.Grid; g != nil {
			out.ChoiceType, out.Options = choiceOptions(g.Columns)
		}
		for _, q := range it.QuestionGroupItem.Questions {
			if q == nil {
				continue
			}
			row := FormRow{QuestionID: q.QuestionId}
			if q.RowQuestion != nil {
				row.Title = q.RowQuestion.Title
			}
			out.Rows = append(out.Rows, row)
		}
	case it.PageBreakItem != nil:
		out.Type = "page_break"
	case it.TextItem != nil:
		out.Type = "text_block"
	case it.ImageItem != nil:
		out.Type = "image"
	case it.VideoItem != nil:
		out.Type = "video"
	default:
		out.Type = "other"
	}
	return out
}

// --- handlers -------------------------------------------------------------------

func (c *Connector) getForm(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, err := idArg(call.Args, "form_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.forms(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	f, err := svc.Forms.Get(id).Context(ctx).Do()
	if err := classify("get form", err); err != nil {
		return connectors.Result{}, err
	}
	out := FormInfo{FormID: id, ResponderURI: f.ResponderUri, Items: []FormItem{}}
	if f.Info != nil {
		out.Title, out.Description = f.Info.Title, f.Info.Description
		if out.Title == "" {
			out.Title = f.Info.DocumentTitle
		}
	}
	for _, it := range f.Items {
		if it != nil {
			out.Items = append(out.Items, toFormItem(it))
		}
	}
	res := connectors.Result{Empty: len(out.Items) == 0}
	fitBody(&out.Description, &out.Truncated, c.bounds.MaxResultBytes, func() any { return out })
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Items) > 1 {
		out.Items = out.Items[:len(out.Items)-1]
		out.Truncated = true
	}
	res.Content, res.Partial = out, out.Truncated
	return res, nil
}

func (c *Connector) listFormResponses(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, err := idArg(call.Args, "form_id")
	if err != nil {
		return connectors.Result{}, err
	}
	maxResults, pageToken, clamped, err := c.pageArgs(call.Args, 25)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.forms(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Forms.Responses.List(id).Context(ctx).PageSize(int64(maxResults))
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	resp, err := req.Do()
	if err := classify("list form responses", err); err != nil {
		return connectors.Result{}, err
	}
	out := FormResponsesPage{FormID: id, MaxResults: maxResults, NextPageToken: resp.NextPageToken, HasMore: resp.NextPageToken != "", Items: []FormResponseItem{}}
	for _, r := range resp.Responses {
		if r != nil {
			out.Items = append(out.Items, toFormResponse(r))
		}
	}
	res := connectors.Result{Empty: len(out.Items) == 0, Partial: clamped}
	max := c.bounds.MaxResultBytes
	for encodedSize(out) > max && len(out.Items) > 1 {
		out.Items = out.Items[:len(out.Items)-1]
		out.Truncated = true
	}
	if len(out.Items) == 1 && encodedSize(out) > max {
		out.Truncated = true // counted while cutting
		last := &out.Items[0]
		for i := len(last.Answers) - 1; i >= 0 && encodedSize(out) > max; i-- {
			values := last.Answers[i].Values
			for j := len(values) - 1; j >= 0 && encodedSize(out) > max; j-- {
				fitBody(&values[j], &last.Truncated, max, func() any { return out })
			}
		}
	}
	res.Content, res.Partial = out, res.Partial || out.Truncated
	return res, nil
}

// toFormResponse flattens a response: answers sorted by question id.
func toFormResponse(r *forms.FormResponse) FormResponseItem {
	out := FormResponseItem{ResponseID: r.ResponseId, CreateTime: r.CreateTime, LastSubmittedTime: r.LastSubmittedTime,
		RespondentEmail: r.RespondentEmail, Answers: []FormAnswer{}}
	for qid, a := range r.Answers {
		ans := FormAnswer{QuestionID: qid, Values: []string{}}
		if a.QuestionId != "" {
			ans.QuestionID = a.QuestionId
		}
		if a.TextAnswers != nil {
			for _, v := range a.TextAnswers.Answers {
				if v != nil {
					ans.Values = append(ans.Values, v.Value)
				}
			}
		}
		if a.FileUploadAnswers != nil {
			for _, f := range a.FileUploadAnswers.Answers {
				if f != nil {
					ans.Values = append(ans.Values, f.FileName)
					ans.FileIDs = append(ans.FileIDs, f.FileId)
				}
			}
		}
		out.Answers = append(out.Answers, ans)
	}
	sort.Slice(out.Answers, func(i, j int) bool { return out.Answers[i].QuestionID < out.Answers[j].QuestionID })
	return out
}
