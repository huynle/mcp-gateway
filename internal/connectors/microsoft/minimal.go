package microsoft

import (
	"encoding/json"
	"strings"
)

// The result shapes every tool returns: flat, snake_case, only the
// fields a harness needs, with the page metadata and truncation flags
// the bounds need. The graph* types are the Graph wire shapes they are
// built from (only the fields read).

// --- Graph wire shapes --------------------------------------------------------

type graphEmailAddress struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

type graphRecipient struct {
	EmailAddress graphEmailAddress `json:"emailAddress"`
}

type graphBody struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
}

type graphMessage struct {
	ID                string           `json:"id"`
	Subject           string           `json:"subject"`
	From              *graphRecipient  `json:"from"`
	ToRecipients      []graphRecipient `json:"toRecipients"`
	CcRecipients      []graphRecipient `json:"ccRecipients"`
	ReceivedDateTime  string           `json:"receivedDateTime"`
	SentDateTime      string           `json:"sentDateTime"`
	BodyPreview       string           `json:"bodyPreview"`
	Body              *graphBody       `json:"body"`
	IsRead            bool             `json:"isRead"`
	HasAttachments    bool             `json:"hasAttachments"`
	ConversationID    string           `json:"conversationId"`
	InternetMessageID string           `json:"internetMessageId"`
	WebLink           string           `json:"webLink"`
}

type graphDateTimeZone struct {
	DateTime string `json:"dateTime"`
	TimeZone string `json:"timeZone"`
}

type graphLocation struct {
	DisplayName string `json:"displayName"`
}

type graphEvent struct {
	ID            string            `json:"id"`
	Subject       string            `json:"subject"`
	IsAllDay      bool              `json:"isAllDay"`
	IsCancelled   bool              `json:"isCancelled"`
	Start         graphDateTimeZone `json:"start"`
	End           graphDateTimeZone `json:"end"`
	Location      *graphLocation    `json:"location"`
	Organizer     *graphRecipient   `json:"organizer"`
	TransactionID string            `json:"transactionId"`
	WebLink       string            `json:"webLink"`
}

type graphParentReference struct {
	DriveID string `json:"driveId"`
	ID      string `json:"id"`
	Path    string `json:"path"`
}

type graphDriveItem struct {
	ID                   string           `json:"id"`
	Name                 string           `json:"name"`
	Size                 int64            `json:"size"`
	WebURL               string           `json:"webUrl"`
	LastModifiedDateTime string           `json:"lastModifiedDateTime"`
	Folder               *json.RawMessage `json:"folder"`
	File                 *struct {
		MimeType string `json:"mimeType"`
	} `json:"file"`
	ParentReference *graphParentReference `json:"parentReference"`
}

type graphTeam struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
}

type graphChannel struct {
	ID             string `json:"id"`
	DisplayName    string `json:"displayName"`
	Description    string `json:"description"`
	MembershipType string `json:"membershipType"`
	WebURL         string `json:"webUrl"`
}

type graphChatMessage struct {
	ID              string `json:"id"`
	CreatedDateTime string `json:"createdDateTime"`
	MessageType     string `json:"messageType"`
	From            *struct {
		User *struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
		} `json:"user"`
	} `json:"from"`
	Body   *graphBody `json:"body"`
	WebURL string     `json:"webUrl"`
}

// --- results ----------------------------------------------------------------------

// MailItem is one mail_search hit.
type MailItem struct {
	ID             string `json:"id"`
	Subject        string `json:"subject"`
	FromName       string `json:"from_name,omitempty"`
	FromAddress    string `json:"from_address,omitempty"`
	ReceivedAt     string `json:"received_at,omitempty"`
	Preview        string `json:"preview,omitempty"`
	IsRead         bool   `json:"is_read"`
	HasAttachments bool   `json:"has_attachments"`
	WebLink        string `json:"web_link,omitempty"`
}

// MailPage is mail_search's result.
type MailPage struct {
	Top       int        `json:"top"`
	HasMore   bool       `json:"has_more"`
	Truncated bool       `json:"truncated,omitempty"`
	Items     []MailItem `json:"items"`
}

// Message is mail_get_message's result.
type Message struct {
	ID              string   `json:"id"`
	Subject         string   `json:"subject"`
	FromName        string   `json:"from_name,omitempty"`
	FromAddress     string   `json:"from_address,omitempty"`
	To              []string `json:"to"`
	CC              []string `json:"cc,omitempty"`
	ReceivedAt      string   `json:"received_at,omitempty"`
	SentAt          string   `json:"sent_at,omitempty"`
	IsRead          bool     `json:"is_read"`
	HasAttachments  bool     `json:"has_attachments"`
	ConversationID  string   `json:"conversation_id,omitempty"`
	WebLink         string   `json:"web_link,omitempty"`
	BodyContentType string   `json:"body_content_type,omitempty"`
	Body            string   `json:"body"`
	// Truncated says the body was cut to fit the result bounds.
	Truncated bool `json:"truncated,omitempty"`
}

// Event is one calendar_list_events item.
type Event struct {
	ID               string `json:"id"`
	Subject          string `json:"subject"`
	Start            string `json:"start"`
	End              string `json:"end"`
	TimeZone         string `json:"time_zone,omitempty"`
	IsAllDay         bool   `json:"is_all_day"`
	IsCancelled      bool   `json:"is_cancelled"`
	Location         string `json:"location,omitempty"`
	OrganizerName    string `json:"organizer_name,omitempty"`
	OrganizerAddress string `json:"organizer_address,omitempty"`
	WebLink          string `json:"web_link,omitempty"`
}

// EventsPage is calendar_list_events's result.
type EventsPage struct {
	Top       int     `json:"top"`
	HasMore   bool    `json:"has_more"`
	Truncated bool    `json:"truncated,omitempty"`
	Items     []Event `json:"items"`
}

// DriveItem is one drive_search hit.
type DriveItem struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	IsFolder   bool   `json:"is_folder"`
	Size       int64  `json:"size,omitempty"`
	MimeType   string `json:"mime_type,omitempty"`
	WebURL     string `json:"web_url,omitempty"`
	ModifiedAt string `json:"modified_at,omitempty"`
	DriveID    string `json:"drive_id,omitempty"`
	ParentID   string `json:"parent_id,omitempty"`
	ParentPath string `json:"parent_path,omitempty"`
}

// DrivePage is drive_search's result.
type DrivePage struct {
	Top       int         `json:"top"`
	HasMore   bool        `json:"has_more"`
	Truncated bool        `json:"truncated,omitempty"`
	Items     []DriveItem `json:"items"`
}

// Channel is one channel of a team.
type Channel struct {
	ID             string `json:"id"`
	DisplayName    string `json:"display_name"`
	Description    string `json:"description,omitempty"`
	MembershipType string `json:"membership_type,omitempty"`
	WebURL         string `json:"web_url,omitempty"`
}

// TeamChannels is one team with its channels; Error says why the
// channels could not be listed (the result is Partial then).
type TeamChannels struct {
	TeamID   string    `json:"team_id"`
	TeamName string    `json:"team_name"`
	Channels []Channel `json:"channels"`
	Error    string    `json:"error,omitempty"`
}

// TeamsPage is teams_list_channels's result.
type TeamsPage struct {
	HasMore   bool           `json:"has_more"`
	Truncated bool           `json:"truncated,omitempty"`
	Items     []TeamChannels `json:"items"`
}

// ChannelMessage is one teams_read_channel_messages item.
type ChannelMessage struct {
	ID          string `json:"id"`
	FromName    string `json:"from_name,omitempty"`
	FromID      string `json:"from_id,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
	MessageType string `json:"message_type,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Content     string `json:"content"`
	WebURL      string `json:"web_url,omitempty"`
}

// ChannelMessagesPage is teams_read_channel_messages's result.
type ChannelMessagesPage struct {
	Top       int              `json:"top"`
	HasMore   bool             `json:"has_more"`
	Truncated bool             `json:"truncated,omitempty"`
	Items     []ChannelMessage `json:"items"`
}

// SentMail is mail_send's result: the identifiers of the sent message,
// never its content. Graph's sendMail answers 202 with no body, so the
// deterministic internet message id is the only id known at once.
type SentMail struct {
	InternetMessageID string `json:"internet_message_id"`
}

// CreatedEvent is calendar_create_event's result.
type CreatedEvent struct {
	ID            string `json:"id"`
	WebLink       string `json:"web_link,omitempty"`
	TransactionID string `json:"transaction_id"`
}

// CreatedFolder is drive_create_folder's result.
type CreatedFolder struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	WebURL   string `json:"web_url,omitempty"`
	DriveID  string `json:"drive_id,omitempty"`
	ParentID string `json:"parent_id,omitempty"`
}

// PostedMessage is teams_post_channel_message's result.
type PostedMessage struct {
	ID        string `json:"id"`
	WebURL    string `json:"web_url,omitempty"`
	TeamID    string `json:"team_id"`
	ChannelID string `json:"channel_id"`
}

// --- converters --------------------------------------------------------------------

func toMailItem(m graphMessage) MailItem {
	out := MailItem{ID: m.ID, Subject: m.Subject, ReceivedAt: m.ReceivedDateTime, Preview: m.BodyPreview, IsRead: m.IsRead, HasAttachments: m.HasAttachments, WebLink: m.WebLink}
	if m.From != nil {
		out.FromName, out.FromAddress = m.From.EmailAddress.Name, m.From.EmailAddress.Address
	}
	return out
}

func toMessage(m graphMessage) Message {
	out := Message{
		ID: m.ID, Subject: m.Subject, To: recipients(m.ToRecipients), CC: recipients(m.CcRecipients),
		ReceivedAt: m.ReceivedDateTime, SentAt: m.SentDateTime, IsRead: m.IsRead, HasAttachments: m.HasAttachments,
		ConversationID: m.ConversationID, WebLink: m.WebLink,
	}
	if m.From != nil {
		out.FromName, out.FromAddress = m.From.EmailAddress.Name, m.From.EmailAddress.Address
	}
	if m.Body != nil {
		out.BodyContentType, out.Body = strings.ToLower(m.Body.ContentType), m.Body.Content
	}
	if out.To == nil {
		out.To = []string{}
	}
	return out
}

// recipients renders "Name <address>" (or just the address).
func recipients(rs []graphRecipient) []string {
	var out []string
	for _, r := range rs {
		a := r.EmailAddress
		switch {
		case a.Name != "" && a.Address != "":
			out = append(out, a.Name+" <"+a.Address+">")
		case a.Address != "":
			out = append(out, a.Address)
		case a.Name != "":
			out = append(out, a.Name)
		}
	}
	return out
}

func toEvent(e graphEvent) Event {
	out := Event{ID: e.ID, Subject: e.Subject, Start: e.Start.DateTime, End: e.End.DateTime, TimeZone: e.Start.TimeZone, IsAllDay: e.IsAllDay, IsCancelled: e.IsCancelled, WebLink: e.WebLink}
	if e.Location != nil {
		out.Location = e.Location.DisplayName
	}
	if e.Organizer != nil {
		out.OrganizerName, out.OrganizerAddress = e.Organizer.EmailAddress.Name, e.Organizer.EmailAddress.Address
	}
	return out
}

func toDriveItem(d graphDriveItem) DriveItem {
	out := DriveItem{ID: d.ID, Name: d.Name, IsFolder: d.Folder != nil, Size: d.Size, WebURL: d.WebURL, ModifiedAt: d.LastModifiedDateTime}
	if d.File != nil {
		out.MimeType = d.File.MimeType
	}
	if d.ParentReference != nil {
		out.DriveID, out.ParentID, out.ParentPath = d.ParentReference.DriveID, d.ParentReference.ID, d.ParentReference.Path
	}
	return out
}

func toChannel(ch graphChannel) Channel {
	return Channel(ch)
}

func toChannelMessage(m graphChatMessage) ChannelMessage {
	out := ChannelMessage{ID: m.ID, CreatedAt: m.CreatedDateTime, MessageType: m.MessageType, WebURL: m.WebURL}
	if m.From != nil && m.From.User != nil {
		out.FromName, out.FromID = m.From.User.DisplayName, m.From.User.ID
	}
	if m.Body != nil {
		out.ContentType, out.Content = strings.ToLower(m.Body.ContentType), m.Body.Content
	}
	return out
}

// encodedSize is the serialised size of v, the measure the bounds apply to.
func encodedSize(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return len(b)
}

// fitBody cuts *body (and sets *truncated) until the object returned by
// obj, which must read both through the same pointers, serialises to at
// most max bytes or the body is gone. Everything but the body stays.
func fitBody(body *string, truncated *bool, max int, obj func() any) {
	if encodedSize(obj()) <= max {
		return
	}
	*truncated = true
	for *body != "" {
		size := encodedSize(obj())
		if size <= max {
			return
		}
		cut := len(*body) - (size - max) - 1
		if cut < 0 {
			cut = 0
		}
		for cut > 0 && cut < len(*body) && !isRuneStart((*body)[cut]) {
			cut--
		}
		*body = (*body)[:cut]
	}
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
