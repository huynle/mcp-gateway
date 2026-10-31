package google

import (
	"context"
	"fmt"
	"net/mail"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"google.golang.org/api/gmail/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Increment 5 (full Gmail): account settings. Reads use gmail.readonly
// (the settings get / list methods accept it, like get_vacation); every
// update needs gmail.settings.basic, the only scope their methods accept.
// Auto-forwarding, forwarding-address creation, send-as creation and
// delegates need gmail.settings.sharing (Workspace admins with
// domain-wide delegation only) and are not built.

// Gmail settings tool names (increment 5).
const (
	ToolListSendAs              = "list_send_as"
	ToolGetImap                 = "get_imap"
	ToolGetPop                  = "get_pop"
	ToolGetAutoForwarding       = "get_auto_forwarding"
	ToolListForwardingAddresses = "list_forwarding_addresses"
	ToolGetLanguage             = "get_language"
	ToolUpdateSignature         = "update_signature"
	ToolUpdateImap              = "update_imap"
	ToolUpdatePop               = "update_pop"
	ToolUpdateLanguage          = "update_language"
)

// MaxSignatureChars bounds update_signature's signature (Gmail's limit).
const MaxSignatureChars = 10_000

// The "setting" values of the settings writes' identities and results,
// and the ids their checks report when found.
const (
	signatureSetting = "signature"
	imapSetting      = "imap"
	popSetting       = "pop"
	languageSetting  = "language"
)

// Values of the IMAP and POP settings.
var (
	expungeBehaviors = []string{"archive", "trash", "deleteForever"}
	maxFolderSizes   = []int{0, 1000, 2000, 5000, 10000}
	popWindows       = []string{"disabled", "fromNowOn", "allMail"}
	popDispositions  = []string{"leaveInInbox", "archive", "trash", "markRead"}
)

// languageRE is the shape of a BCP 47 language tag.
var languageRE = regexp.MustCompile(`^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$`)

// SendAs is one list_send_as item.
type SendAs struct {
	SendAsEmail        string `json:"send_as_email"`
	DisplayName        string `json:"display_name,omitempty"`
	ReplyTo            string `json:"reply_to,omitempty"`
	Signature          string `json:"signature,omitempty"`
	IsPrimary          bool   `json:"is_primary,omitempty"`
	IsDefault          bool   `json:"is_default,omitempty"`
	TreatAsAlias       bool   `json:"treat_as_alias,omitempty"`
	VerificationStatus string `json:"verification_status,omitempty"`
}

// SendAsPage is list_send_as's result (Gmail returns every alias at once).
type SendAsPage struct {
	Truncated bool     `json:"truncated,omitempty"`
	Items     []SendAs `json:"items"`
}

// SignatureUpdate is update_signature's result: never the signature.
type SignatureUpdate struct {
	SendAsEmail string `json:"send_as_email"`
	Updated     bool   `json:"updated"`
}

// ImapSettings is get_imap's and update_imap's result.
type ImapSettings struct {
	Enabled         bool   `json:"enabled"`
	AutoExpunge     bool   `json:"auto_expunge"`
	ExpungeBehavior string `json:"expunge_behavior,omitempty"`
	MaxFolderSize   int64  `json:"max_folder_size"`
}

// PopSettings is get_pop's and update_pop's result.
type PopSettings struct {
	AccessWindow string `json:"access_window,omitempty"`
	Disposition  string `json:"disposition,omitempty"`
}

// AutoForwarding is get_auto_forwarding's result.
type AutoForwarding struct {
	Enabled      bool   `json:"enabled"`
	EmailAddress string `json:"email_address,omitempty"`
	Disposition  string `json:"disposition,omitempty"`
}

// ForwardingAddress is one list_forwarding_addresses item.
type ForwardingAddress struct {
	ForwardingEmail    string `json:"forwarding_email"`
	VerificationStatus string `json:"verification_status,omitempty"`
}

// ForwardingAddresses is list_forwarding_addresses's result.
type ForwardingAddresses struct {
	Items []ForwardingAddress `json:"items"`
}

// Language is get_language's and update_language's result.
type Language struct {
	DisplayLanguage string `json:"display_language"`
}

func (c *Connector) gmailPrefsReadTools() []connectors.Tool {
	read := func(name, description string) connectors.Tool {
		return connectors.Tool{
			App: AppGmail, Name: name, Kind: connectors.KindRead, Description: description,
			InputSchema: objectSchema(nil, nil), RequiredScopes: []string{ScopeGmailReadonly}, ResourceIdentity: noIdentity, Bounds: c.singleBounds(),
		}
	}
	return []connectors.Tool{
		read(ToolListSendAs, "List the addresses the Gmail account can send as (the primary address and aliases): send_as_email, display_name, "+
			"reply_to, signature (HTML), is_primary, is_default, treat_as_alias and verification_status. Signatures are cut to the result bounds."),
		read(ToolGetImap, "Get the Gmail account's IMAP settings: enabled, auto_expunge, expunge_behavior (archive, trash, deleteForever) and "+
			"max_folder_size (0 = no limit)."),
		read(ToolGetPop, "Get the Gmail account's POP settings: access_window (disabled, fromNowOn, allMail) and disposition (leaveInInbox, "+
			"archive, trash, markRead)."),
		read(ToolGetAutoForwarding, "Get the Gmail account's automatic forwarding: enabled, the address mail is forwarded to and what happens "+
			"to the forwarded mail (disposition). Changing it is not possible through the gateway."),
		read(ToolListForwardingAddresses, "List the Gmail account's forwarding addresses and their verification status; only accepted "+
			"addresses can be a filter's forward action."),
		read(ToolGetLanguage, "Get the Gmail account's display language (a BCP 47 tag such as en-GB)."),
	}
}

func (c *Connector) gmailPrefsReadHandlers() map[string]handler {
	return map[string]handler{
		ToolListSendAs: c.listSendAs, ToolGetImap: c.getImap, ToolGetPop: c.getPop, ToolGetAutoForwarding: c.getAutoForwarding,
		ToolListForwardingAddresses: c.listForwardingAddresses, ToolGetLanguage: c.getLanguage,
	}
}

func (c *Connector) gmailPrefsWriteTools() []connectors.Tool {
	settingIDs := func(res connectors.Result) map[string]string {
		switch v := res.Content.(type) {
		case SignatureUpdate:
			return map[string]string{"setting": signatureSetting, "send_as_domain": domainOf(v.SendAsEmail)}
		case ImapSettings:
			return map[string]string{"setting": imapSetting}
		case PopSettings:
			return map[string]string{"setting": popSetting}
		case Language:
			return map[string]string{"setting": languageSetting, "display_language": v.DisplayLanguage}
		}
		return nil
	}
	return []connectors.Tool{
		{
			App: AppGmail, Name: ToolUpdateSignature, Kind: connectors.KindWrite,
			Description: fmt.Sprintf("Set the signature of one of the Gmail account's send-as addresses (list_send_as): HTML or plain text, at most %d characters; ", MaxSignatureChars) +
				"an empty signature removes it. Returns the address, never the signature.",
			InputSchema: objectSchema([]property{
				{"send_as_email", "string", "The send-as address (the primary address or an alias, from list_send_as).", nil},
				{"signature", "string", "The new signature (HTML allowed); empty removes it.", nil},
			}, []string{"send_as_email", "signature"}),
			RequiredScopes:   []string{ScopeGmailSettingsBasic},
			ResourceIdentity: signatureIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
			ResultIDs:        settingIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppGmail, Name: ToolUpdateImap, Kind: connectors.KindWrite,
			Description: "Change the Gmail account's IMAP settings; only what is given changes: enabled, auto_expunge, expunge_behavior " +
				"(archive, trash, deleteForever: what happens to a message deleted over IMAP) and max_folder_size (0, 1000, 2000, 5000, 10000).",
			InputSchema: objectSchema([]property{
				{"enabled", "boolean", "Turn IMAP access on or off.", nil},
				{"auto_expunge", "boolean", "Expunge a message as soon as it is marked deleted over IMAP.", nil},
				{"expunge_behavior", "string", "What happens to an expunged message: archive, trash or deleteForever.", expungeBehaviors},
				{"max_folder_size", "integer", "Most messages an IMAP folder shows: 0 (no limit), 1000, 2000, 5000 or 10000.", nil},
			}, nil),
			RequiredScopes:   []string{ScopeGmailSettingsBasic},
			ResourceIdentity: settingsIdentity(imapSetting, parseImapArgs),
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkSettings(imapSetting, c.currentImap)},
			ResultIDs:        settingIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppGmail, Name: ToolUpdatePop, Kind: connectors.KindWrite,
			Description: "Change the Gmail account's POP settings; only what is given changes: access_window (disabled, fromNowOn, allMail) " +
				"and disposition (what happens to a message fetched over POP: leaveInInbox, archive, trash, markRead).",
			InputSchema: objectSchema([]property{
				{"access_window", "string", "Which messages POP can fetch: disabled, fromNowOn or allMail.", popWindows},
				{"disposition", "string", "What happens to a fetched message: leaveInInbox, archive, trash or markRead.", popDispositions},
			}, nil),
			RequiredScopes:   []string{ScopeGmailSettingsBasic},
			ResourceIdentity: settingsIdentity(popSetting, parsePopArgs),
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkSettings(popSetting, c.currentPop)},
			ResultIDs:        settingIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppGmail, Name: ToolUpdateLanguage, Kind: connectors.KindWrite,
			Description: "Change the Gmail account's display language (a BCP 47 tag such as en, en-GB, fr, de). Gmail may store a close " +
				"supported language instead; the result says which.",
			InputSchema:      objectSchema([]property{{"display_language", "string", "The language tag.", nil}}, []string{"display_language"}),
			RequiredScopes:   []string{ScopeGmailSettingsBasic},
			ResourceIdentity: languageIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkLanguage},
			ResultIDs:        settingIDs,
			Bounds:           c.singleBounds(),
		},
	}
}

func (c *Connector) gmailPrefsWriteHandlers() map[string]handler {
	return map[string]handler{
		ToolUpdateSignature: c.updateSignature, ToolUpdateImap: c.updateImap, ToolUpdatePop: c.updatePop, ToolUpdateLanguage: c.updateLanguage,
	}
}

// --- arguments and identities ----------------------------------------------------

// settingFields are a settings update's validated fields: the API field
// name to the value given (bool, string or int64), and the identity
// value of each (by argument name).
type settingFields struct {
	values   map[string]any    // Gmail field -> value
	identity map[string]string // argument -> canonical string
}

// knownArgs refuses arguments a settings write does not take (beyond
// the gateway's own account and approval_id).
func knownArgs(args map[string]any, names ...string) error {
	for k := range args {
		if k != "account" && k != "approval_id" && !slices.Contains(names, k) {
			return invalid("unknown argument %q (known: %s)", k, strings.Join(names, ", "))
		}
	}
	return nil
}

func parseImapArgs(args map[string]any) (settingFields, error) {
	f := settingFields{values: map[string]any{}, identity: map[string]string{}}
	if err := knownArgs(args, "enabled", "auto_expunge", "expunge_behavior", "max_folder_size"); err != nil {
		return f, err
	}
	for arg, field := range map[string]string{"enabled": "Enabled", "auto_expunge": "AutoExpunge"} {
		if _, given := args[arg]; !given {
			continue
		}
		v, err := optionalBool(args, arg, false)
		if err != nil {
			return f, err
		}
		f.values[field], f.identity[arg] = v, strconv.FormatBool(v)
	}
	if _, given := args["expunge_behavior"]; given {
		v, err := optionalString(args, "expunge_behavior")
		if err != nil || !slices.Contains(expungeBehaviors, v) {
			return f, invalid("expunge_behavior must be archive, trash or deleteForever")
		}
		f.values["ExpungeBehavior"], f.identity["expunge_behavior"] = v, v
	}
	if raw, given := args["max_folder_size"]; given {
		n, err := toInt(raw)
		if err != nil || !slices.Contains(maxFolderSizes, n) {
			return f, invalid("max_folder_size must be 0, 1000, 2000, 5000 or 10000")
		}
		f.values["MaxFolderSize"], f.identity["max_folder_size"] = int64(n), strconv.Itoa(n)
	}
	if len(f.values) == 0 {
		return f, invalid("give enabled, auto_expunge, expunge_behavior or max_folder_size")
	}
	return f, nil
}

func parsePopArgs(args map[string]any) (settingFields, error) {
	f := settingFields{values: map[string]any{}, identity: map[string]string{}}
	if err := knownArgs(args, "access_window", "disposition"); err != nil {
		return f, err
	}
	for _, p := range []struct {
		arg, field string
		values     []string
	}{{"access_window", "AccessWindow", popWindows}, {"disposition", "Disposition", popDispositions}} {
		if _, given := args[p.arg]; !given {
			continue
		}
		v, err := optionalString(args, p.arg)
		if err != nil || !slices.Contains(p.values, v) {
			return f, invalid("%s must be one of %s", p.arg, strings.Join(p.values, ", "))
		}
		f.values[p.field], f.identity[p.arg] = v, v
	}
	if len(f.values) == 0 {
		return f, invalid("give access_window or disposition")
	}
	return f, nil
}

// settingsIdentity is a settings write's identity: setting plus the
// values asked for (none of them content).
func settingsIdentity(setting string, parse func(map[string]any) (settingFields, error)) func(map[string]any) map[string]string {
	return func(args map[string]any) map[string]string {
		out := map[string]string{"setting": setting}
		if f, err := parse(args); err == nil {
			for k, v := range f.identity {
				out[k] = v
			}
		}
		return out
	}
}

func signatureIdentity(args map[string]any) map[string]string {
	out := map[string]string{"setting": signatureSetting}
	if v, _ := args["send_as_email"].(string); v != "" {
		if addr, err := mail.ParseAddress(v); err == nil {
			out["send_as_domain"] = domainOf(addr.Address)
		}
	}
	return out
}

func parseLanguage(args map[string]any) (string, error) {
	v, err := requiredString(args, "display_language")
	if err != nil || !languageRE.MatchString(v) {
		return "", invalid("display_language must be a language tag such as en, en-GB or fr")
	}
	return v, nil
}

func languageIdentity(args map[string]any) map[string]string {
	out := map[string]string{"setting": languageSetting}
	if v, err := parseLanguage(args); err == nil {
		out["display_language"] = strings.ToLower(v)
	}
	return out
}

// --- conversions ------------------------------------------------------------------

func toImap(s *gmail.ImapSettings) ImapSettings {
	return ImapSettings{Enabled: s.Enabled, AutoExpunge: s.AutoExpunge, ExpungeBehavior: s.ExpungeBehavior, MaxFolderSize: s.MaxFolderSize}
}

func toPop(s *gmail.PopSettings) PopSettings {
	return PopSettings{AccessWindow: s.AccessWindow, Disposition: s.Disposition}
}

// imapValues and popValues give a settings object's values in the
// identity's form (argument -> canonical string), for the checks.
func imapValues(s ImapSettings) map[string]string {
	return map[string]string{
		"enabled": strconv.FormatBool(s.Enabled), "auto_expunge": strconv.FormatBool(s.AutoExpunge),
		"expunge_behavior": s.ExpungeBehavior, "max_folder_size": strconv.FormatInt(s.MaxFolderSize, 10),
	}
}

func popValues(s PopSettings) map[string]string {
	return map[string]string{"access_window": s.AccessWindow, "disposition": s.Disposition}
}

// --- read handlers ----------------------------------------------------------------

func (c *Connector) listSendAs(ctx context.Context, cl *client, _ connectors.Call) (connectors.Result, error) {
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	resp, err := svc.Users.Settings.SendAs.List(gmailUser).Context(ctx).Do()
	if err := classify("list send-as addresses", err); err != nil {
		return connectors.Result{}, err
	}
	out := SendAsPage{Items: []SendAs{}}
	for _, s := range resp.SendAs {
		if s == nil {
			continue
		}
		out.Items = append(out.Items, SendAs{
			SendAsEmail: s.SendAsEmail, DisplayName: s.DisplayName, ReplyTo: s.ReplyToAddress, Signature: s.Signature,
			IsPrimary: s.IsPrimary, IsDefault: s.IsDefault, TreatAsAlias: s.TreatAsAlias, VerificationStatus: s.VerificationStatus,
		})
	}
	res := connectors.Result{Empty: len(out.Items) == 0}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Items) > 1 {
		out.Items = out.Items[:len(out.Items)-1]
		out.Truncated, res.Partial = true, true
	}
	if len(out.Items) == 1 {
		fitBody(&out.Items[0].Signature, &out.Truncated, c.bounds.MaxResultBytes, func() any { return out })
		res.Partial = res.Partial || out.Truncated
	}
	res.Content = out
	return res, nil
}

func (c *Connector) currentImap(ctx context.Context, svc *gmail.Service) (map[string]string, error) {
	s, err := svc.Users.Settings.GetImap(gmailUser).Context(ctx).Do()
	if err := classify("get IMAP settings", err); err != nil {
		return nil, err
	}
	return imapValues(toImap(s)), nil
}

func (c *Connector) currentPop(ctx context.Context, svc *gmail.Service) (map[string]string, error) {
	s, err := svc.Users.Settings.GetPop(gmailUser).Context(ctx).Do()
	if err := classify("get POP settings", err); err != nil {
		return nil, err
	}
	return popValues(toPop(s)), nil
}

func (c *Connector) getImap(ctx context.Context, cl *client, _ connectors.Call) (connectors.Result, error) {
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	s, err := svc.Users.Settings.GetImap(gmailUser).Context(ctx).Do()
	if err := classify("get IMAP settings", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toImap(s)}, nil
}

func (c *Connector) getPop(ctx context.Context, cl *client, _ connectors.Call) (connectors.Result, error) {
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	s, err := svc.Users.Settings.GetPop(gmailUser).Context(ctx).Do()
	if err := classify("get POP settings", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toPop(s)}, nil
}

func (c *Connector) getAutoForwarding(ctx context.Context, cl *client, _ connectors.Call) (connectors.Result, error) {
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	s, err := svc.Users.Settings.GetAutoForwarding(gmailUser).Context(ctx).Do()
	if err := classify("get auto-forwarding", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: AutoForwarding{Enabled: s.Enabled, EmailAddress: s.EmailAddress, Disposition: s.Disposition}}, nil
}

func (c *Connector) listForwardingAddresses(ctx context.Context, cl *client, _ connectors.Call) (connectors.Result, error) {
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	resp, err := svc.Users.Settings.ForwardingAddresses.List(gmailUser).Context(ctx).Do()
	if err := classify("list forwarding addresses", err); err != nil {
		return connectors.Result{}, err
	}
	out := ForwardingAddresses{Items: []ForwardingAddress{}}
	for _, a := range resp.ForwardingAddresses {
		if a != nil && a.ForwardingEmail != "" {
			out.Items = append(out.Items, ForwardingAddress{ForwardingEmail: a.ForwardingEmail, VerificationStatus: a.VerificationStatus})
		}
	}
	return connectors.Result{Content: out, Empty: len(out.Items) == 0}, nil
}

func (c *Connector) getLanguage(ctx context.Context, cl *client, _ connectors.Call) (connectors.Result, error) {
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	s, err := svc.Users.Settings.GetLanguage(gmailUser).Context(ctx).Do()
	if err := classify("get language", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: Language{DisplayLanguage: s.DisplayLanguage}}, nil
}

// --- write handlers ---------------------------------------------------------------

func (c *Connector) updateSignature(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	raw, err := requiredString(call.Args, "send_as_email")
	if err != nil {
		return connectors.Result{}, err
	}
	addr, err := mail.ParseAddress(raw)
	if err != nil {
		return connectors.Result{}, invalid("send_as_email must be an email address (from list_send_as)")
	}
	sig, ok := call.Args["signature"].(string)
	if !ok {
		return connectors.Result{}, invalid("signature is required (a string; empty removes it)")
	}
	if utf8.RuneCountInString(sig) > MaxSignatureChars {
		return connectors.Result{}, invalid("signature is longer than %d characters", MaxSignatureChars)
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	_, err = svc.Users.Settings.SendAs.Patch(gmailUser, addr.Address, &gmail.SendAs{Signature: sig, ForceSendFields: []string{"Signature"}}).Context(ctx).Do()
	if err := classifyWrite("update signature", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: SignatureUpdate{SendAsEmail: addr.Address, Updated: true}}, nil
}

// updateImap reads the IMAP settings (updateImap replaces them all; the
// read failing is a known outcome), applies the given fields and writes
// them back with every field sent (false and 0 included).
func (c *Connector) updateImap(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	f, err := parseImapArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	cur, err := svc.Users.Settings.GetImap(gmailUser).Context(ctx).Do()
	if err := classify("get IMAP settings", err); err != nil {
		return connectors.Result{}, err
	}
	next := &gmail.ImapSettings{Enabled: cur.Enabled, AutoExpunge: cur.AutoExpunge, ExpungeBehavior: cur.ExpungeBehavior, MaxFolderSize: cur.MaxFolderSize,
		ForceSendFields: []string{"Enabled", "AutoExpunge", "MaxFolderSize"}}
	for field, v := range f.values {
		switch field {
		case "Enabled":
			next.Enabled = v.(bool)
		case "AutoExpunge":
			next.AutoExpunge = v.(bool)
		case "ExpungeBehavior":
			next.ExpungeBehavior = v.(string)
		case "MaxFolderSize":
			next.MaxFolderSize = v.(int64)
		}
	}
	got, err := svc.Users.Settings.UpdateImap(gmailUser, next).Context(ctx).Do()
	if err := classifyWrite("update IMAP settings", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toImap(got)}, nil
}

func (c *Connector) updatePop(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	f, err := parsePopArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	cur, err := svc.Users.Settings.GetPop(gmailUser).Context(ctx).Do()
	if err := classify("get POP settings", err); err != nil {
		return connectors.Result{}, err
	}
	next := &gmail.PopSettings{AccessWindow: cur.AccessWindow, Disposition: cur.Disposition}
	if v, ok := f.values["AccessWindow"].(string); ok {
		next.AccessWindow = v
	}
	if v, ok := f.values["Disposition"].(string); ok {
		next.Disposition = v
	}
	got, err := svc.Users.Settings.UpdatePop(gmailUser, next).Context(ctx).Do()
	if err := classifyWrite("update POP settings", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toPop(got)}, nil
}

func (c *Connector) updateLanguage(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	lang, err := parseLanguage(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	got, err := svc.Users.Settings.UpdateLanguage(gmailUser, &gmail.LanguageSettings{DisplayLanguage: lang}).Context(ctx).Do()
	if err := classifyWrite("update language", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: Language{DisplayLanguage: got.DisplayLanguage}}, nil
}

// --- reconciliation ---------------------------------------------------------------

// checkSettings is a settings write's state check: the settings are read
// back and every value the identity recorded must match (found, with the
// setting's name); any difference is not_found (the update replaces the
// settings at once). Any read error is "cannot tell yet".
func (c *Connector) checkSettings(setting string, current func(context.Context, *gmail.Service) (map[string]string, error)) func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return func(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
		tg, err := c.target(in)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		if in.ResourceIdentity["setting"] != setting || len(in.ResourceIdentity) < 2 {
			return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity names no %s setting", ErrNotReconcilable, setting)
		}
		ctx, cancel := context.WithTimeout(ctx, c.timeout)
		defer cancel()
		svc, err := tg.client.gmail(ctx)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		got, err := current(ctx, svc)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		for key, want := range in.ResourceIdentity {
			if key != "setting" && got[key] != want {
				return notFound, nil
			}
		}
		return found(setting), nil
	}
}

// checkLanguage: the display language equal to the one asked for (case
// aside) is found. Gmail may store a close supported language instead,
// so another language cannot tell (never not_found); any error is
// "cannot tell yet".
func (c *Connector) checkLanguage(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	want := in.ResourceIdentity["display_language"]
	if want == "" {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no language", ErrNotReconcilable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.gmail(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	s, err := svc.Users.Settings.GetLanguage(gmailUser).Context(ctx).Do()
	if err := classify("reconcile: get language", err); err != nil {
		return connectors.ReconcileResult{}, err
	}
	if strings.EqualFold(s.DisplayLanguage, want) {
		return found(languageSetting), nil
	}
	return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: the display language is %q, not %q (Gmail may store a close language); cannot tell", s.DisplayLanguage, want)
}
