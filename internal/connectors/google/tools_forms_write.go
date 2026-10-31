package google

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/api/forms/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Forms tool names (increment 5).
const (
	ToolCreateForm         = "create"
	ToolSetPublishSettings = "set_publish_settings"
	ToolGetResponse        = "get_response"
)

// MimeForm is the Google Forms MIME type forms.create creates.
const MimeForm = "application/vnd.google-apps.form"

// CreatedForm is forms.create's result: the new form's identifiers and
// whether its title and description went in (InfoStatus applied, failed
// or unknown; InfoError says why not).
type CreatedForm struct {
	ID         string   `json:"id"`
	URL        string   `json:"url,omitempty"`
	Parents    []string `json:"parents,omitempty"`
	DriveID    string   `json:"drive_id,omitempty"`
	InfoStatus string   `json:"info_status"`
	InfoError  string   `json:"info_error,omitempty"`
}

// FormPublishState is set_publish_settings' result.
type FormPublishState struct {
	FormID             string `json:"form_id"`
	Published          bool   `json:"published"`
	AcceptingResponses bool   `json:"accepting_responses"`
	ResponderURI       string `json:"responder_uri,omitempty"`
}

func (c *Connector) formsFullReadTools() []connectors.Tool {
	return []connectors.Tool{{
		App: AppForms, Name: ToolGetResponse, Kind: connectors.KindRead,
		Description: "Get one response of a Google Form by its response_id (from list_responses): create_time, last_submitted_time, " +
			"respondent_email (when collected) and answers (question_id with values; file uploads give file names and Drive file_ids).",
		InputSchema: objectSchema([]property{
			formIDProperty,
			{"response_id", "string", "The response's id (response_id of list_responses).", nil},
		}, []string{"form_id", "response_id"}),
		RequiredScopes: []string{ScopeFormsResponsesReadonly},
		ResourceIdentity: func(args map[string]any) map[string]string {
			out := formIdentity(args)
			if id, _ := args["response_id"].(string); strings.TrimSpace(id) != "" {
				out["response_id"] = strings.TrimSpace(id)
			}
			return out
		},
		Bounds: c.singleBounds(),
	}}
}

func (c *Connector) formsFullReadHandlers() map[string]handler {
	return map[string]handler{ToolGetResponse: c.getFormResponse}
}

func (c *Connector) formsWriteTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppForms, Name: ToolCreateForm, Kind: connectors.KindWrite,
			Description: "Create an empty Google Form with a title (and description), in the root of My Drive, under parent_id, or in the " +
				"shared drive drive_id. Returns the new form's id and edit url; add questions with forms.batch_update (createItem) " +
				"and publish it with set_publish_settings.",
			InputSchema: objectSchema([]property{
				{"title", "string", "The form's title (also its file name).", nil},
				{"description", "string", "The form's description, shown to respondents.", nil},
				{"parent_id", "string", "Id of the folder to create it in; the root of My Drive (or of drive_id) when omitted.", nil},
				{"drive_id", "string", "Shared drive to create it in (its root when parent_id is omitted).", nil},
			}, []string{"title"}),
			RequiredScopes:   []string{ScopeDriveFile},
			ResourceIdentity: driveIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkDriveMarker},
			ResultIDs: func(res connectors.Result) map[string]string {
				if v, ok := res.Content.(CreatedForm); ok && v.ID != "" {
					return map[string]string{"id": v.ID, "url": v.URL}
				}
				return nil
			},
			Bounds: c.singleBounds(),
		},
		{
			App: AppForms, Name: ToolSetPublishSettings, Kind: connectors.KindWrite,
			Description: "Publish or unpublish a Google Form and open or close it for responses: published (required), accepting_responses " +
				"(default: the same as published; cannot be true for an unpublished form). Forms created before publishing existed " +
				"(legacy forms) cannot be changed this way.",
			InputSchema: objectSchema([]property{
				formIDProperty,
				{"published", "boolean", "Whether the form is published (visible to respondents).", nil},
				{"accepting_responses", "boolean", "Whether the form accepts responses (default: published).", nil},
			}, []string{"form_id", "published"}),
			RequiredScopes:   []string{ScopeFormsBody},
			ResourceIdentity: publishIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkPublishSettings},
			ResultIDs: func(res connectors.Result) map[string]string {
				if v, ok := res.Content.(FormPublishState); ok && v.FormID != "" {
					return map[string]string{"form_id": v.FormID, "published": strconv.FormatBool(v.Published)}
				}
				return nil
			},
			Bounds: c.singleBounds(),
		},
		c.batchTool(formsBatch),
	}
}

func (c *Connector) formsWriteHandlers() map[string]handler {
	return map[string]handler{ToolCreateForm: c.createForm, ToolSetPublishSettings: c.setPublishSettings, ToolBatchUpdate: c.batchHandler(formsBatch)}
}

// publishIdentity is form_id, published and accepting_responses (the
// state the write sets, defaulting as the handler does): the check
// compares the form's state with it.
func publishIdentity(args map[string]any) map[string]string {
	out := formIdentity(args)
	published, ok := args["published"].(bool)
	if !ok {
		return out
	}
	accepting := published
	if v, ok := args["accepting_responses"].(bool); ok {
		accepting = v
	}
	out["published"], out["accepting_responses"] = strconv.FormatBool(published), strconv.FormatBool(accepting)
	return out
}

// publishArgs reads published and accepting_responses.
func publishArgs(args map[string]any) (published, accepting bool, err error) {
	if _, ok := args["published"]; !ok {
		return false, false, invalid("published is required")
	}
	if published, err = optionalBool(args, "published", false); err != nil {
		return false, false, err
	}
	if accepting, err = optionalBool(args, "accepting_responses", published); err != nil {
		return false, false, err
	}
	if accepting && !published {
		return false, false, invalid("an unpublished form cannot accept responses: set published true or accepting_responses false")
	}
	return published, accepting, nil
}

// createForm creates the form through Drive (files.create with the Forms
// MIME type and the operation's marker, one request, like docs.create),
// then sets its title and description with the Forms API
// (updateFormInfo). Once the file exists the write succeeded whatever
// the second request does (InfoStatus).
func (c *Connector) createForm(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	title, err := requiredString(call.Args, "title")
	if err != nil {
		return connectors.Result{}, err
	}
	description, err := textArg(call.Args, "description", false)
	if err != nil {
		return connectors.Result{}, err
	}
	f, err := newDriveFile(call, title, MimeForm)
	if err != nil {
		return connectors.Result{}, err
	}
	driveSvc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	created, err := driveSvc.Files.Create(f).Context(ctx).SupportsAllDrives(true).Fields(createdFileFields).Do()
	if err := classifyWrite("create form", err); err != nil {
		return connectors.Result{}, err
	}
	out := CreatedForm{ID: created.Id, URL: created.WebViewLink, Parents: created.Parents, DriveID: created.DriveId, InfoStatus: BodyApplied}
	info, mask := &forms.Info{Title: title}, "title"
	if description != "" {
		info.Description, mask = description, "title,description"
	}
	formsSvc, err := cl.forms(ctx)
	if err == nil {
		req := &forms.BatchUpdateFormRequest{Requests: []*forms.Request{{UpdateFormInfo: &forms.UpdateFormInfoRequest{Info: info, UpdateMask: mask}}}}
		_, err = formsSvc.Forms.BatchUpdate(out.ID, req).Context(ctx).Do()
		err = classifyWrite("set the form's title", err)
	}
	if err != nil {
		out.InfoStatus, out.InfoError = BodyFailed, err.Error()
		if errors.Is(err, connectors.ErrOutcomeUnknown) {
			out.InfoStatus = BodyUnknown
		}
	}
	return connectors.Result{Content: out}, nil
}

func (c *Connector) setPublishSettings(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, err := idArg(call.Args, "form_id")
	if err != nil {
		return connectors.Result{}, err
	}
	published, accepting, err := publishArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.forms(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	state := &forms.PublishState{IsPublished: published, IsAcceptingResponses: accepting, ForceSendFields: []string{"IsPublished", "IsAcceptingResponses"}}
	req := &forms.SetPublishSettingsRequest{PublishSettings: &forms.PublishSettings{PublishState: state}, UpdateMask: "publish_state"}
	resp, err := svc.Forms.SetPublishSettings(id, req).Context(ctx).Do()
	if err := classifyWrite("set publish settings", err); err != nil {
		return connectors.Result{}, err
	}
	out := FormPublishState{FormID: id, Published: published, AcceptingResponses: accepting}
	if resp.PublishSettings != nil && resp.PublishSettings.PublishState != nil {
		out.Published, out.AcceptingResponses = resp.PublishSettings.PublishState.IsPublished, resp.PublishSettings.PublishState.IsAcceptingResponses
	}
	return connectors.Result{Content: out}, nil
}

func (c *Connector) getFormResponse(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, err := idArg(call.Args, "form_id")
	if err != nil {
		return connectors.Result{}, err
	}
	responseID, err := idArg(call.Args, "response_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.forms(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	r, err := svc.Forms.Responses.Get(id, responseID).Context(ctx).Do()
	if err := classify("get form response", err); err != nil {
		return connectors.Result{}, err
	}
	out := toFormResponse(r)
	if out.ResponseID == "" {
		out.ResponseID = responseID
	}
	max := c.bounds.MaxResultBytes
	for i := len(out.Answers) - 1; i >= 0 && encodedSize(out) > max; i-- {
		values := out.Answers[i].Values
		for j := len(values) - 1; j >= 0 && encodedSize(out) > max; j-- {
			fitBody(&values[j], &out.Truncated, max, func() any { return out })
		}
	}
	return connectors.Result{Content: out, Empty: len(out.Answers) == 0, Partial: out.Truncated}, nil
}

// checkPublishSettings is set_publish_settings' state check: the form's
// publish state equal to the identity's is found, a different one
// not_found (the state is replaced at once); a form without publish
// settings (a legacy form) or any error is "cannot tell yet".
func (c *Connector) checkPublishSettings(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	id, published, accepting := in.ResourceIdentity["form_id"], in.ResourceIdentity["published"], in.ResourceIdentity["accepting_responses"]
	if id == "" || !idRE.MatchString(id) || published == "" || accepting == "" {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no form or publish state", ErrNotReconcilable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.forms(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	f, err := svc.Forms.Get(id).Context(ctx).Fields("formId,publishSettings").Do()
	if err := classify("reconcile: get form", err); err != nil {
		return connectors.ReconcileResult{}, err
	}
	if f.PublishSettings == nil {
		return connectors.ReconcileResult{}, errors.New("google: reconcile: the form has no publish settings (a legacy form); cannot tell")
	}
	state := f.PublishSettings.PublishState
	if state == nil {
		state = &forms.PublishState{}
	}
	if strconv.FormatBool(state.IsPublished) == published && strconv.FormatBool(state.IsAcceptingResponses) == accepting {
		return found(id), nil
	}
	return notFound, nil
}
