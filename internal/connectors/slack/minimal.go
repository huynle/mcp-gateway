// Message, channel and search result shapes are adapted from
// korotovsky/slack-mcp-server, pkg/handler/conversations.go (Message)
// and pkg/handler/channels.go (commit
// b88c0de3f706f4f07337c9eda7133c736d1c9524), MIT License, Copyright (c)
// 2025 Dmitrii Korotovskii. Modified for mcp-gateway: JSON objects
// instead of CSV rows, no user-name resolution (ids only; get_user
// resolves one), reactions as objects, page metadata and the truncation
// flags the bounds need, thread_ts of a search hit from its permalink.
// See THIRD_PARTY_NOTICES.md.

package slack

import (
	"encoding/json"
	"net/url"
	"time"

	goslack "github.com/slack-go/slack"
)

// Channel is one conversation of list_channels.
type Channel struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	IsPrivate  bool   `json:"is_private"`
	IsArchived bool   `json:"is_archived"`
	IsMember   bool   `json:"is_member"`
	NumMembers int    `json:"num_members,omitempty"`
	Topic      string `json:"topic,omitempty"`
	Purpose    string `json:"purpose,omitempty"`
	Created    string `json:"created,omitempty"`
}

// ChannelsPage is list_channels's result.
type ChannelsPage struct {
	Channels   []Channel `json:"channels"`
	NextCursor string    `json:"next_cursor,omitempty"`
	HasMore    bool      `json:"has_more"`
	Limit      int       `json:"limit"`
	Truncated  bool      `json:"truncated,omitempty"`
}

// Reaction is one emoji reaction on a message.
type Reaction struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Message is one message of read_channel_history, get_thread or
// search_messages. Users are ids; get_user names one.
type Message struct {
	TS          string     `json:"ts"`
	ThreadTS    string     `json:"thread_ts,omitempty"`
	User        string     `json:"user,omitempty"`
	Username    string     `json:"username,omitempty"`
	BotID       string     `json:"bot_id,omitempty"`
	Text        string     `json:"text"`
	Subtype     string     `json:"subtype,omitempty"`
	ReplyCount  int        `json:"reply_count,omitempty"`
	Edited      bool       `json:"edited,omitempty"`
	Reactions   []Reaction `json:"reactions,omitempty"`
	FileCount   int        `json:"file_count,omitempty"`
	Channel     string     `json:"channel,omitempty"`
	ChannelName string     `json:"channel_name,omitempty"`
	Permalink   string     `json:"permalink,omitempty"`
	Time        string     `json:"time,omitempty"`
}

// HistoryPage is read_channel_history's result.
type HistoryPage struct {
	Channel     string    `json:"channel"`
	ChannelName string    `json:"channel_name,omitempty"`
	Messages    []Message `json:"messages"`
	HasMore     bool      `json:"has_more"`
	NextCursor  string    `json:"next_cursor,omitempty"`
	Limit       int       `json:"limit"`
	Truncated   bool      `json:"truncated,omitempty"`
}

// ThreadPage is get_thread's result.
type ThreadPage struct {
	Channel     string    `json:"channel"`
	ChannelName string    `json:"channel_name,omitempty"`
	ThreadTS    string    `json:"thread_ts"`
	Messages    []Message `json:"messages"`
	HasMore     bool      `json:"has_more"`
	NextCursor  string    `json:"next_cursor,omitempty"`
	Limit       int       `json:"limit"`
	Truncated   bool      `json:"truncated,omitempty"`
}

// SearchPage is search_messages's result.
type SearchPage struct {
	Total     int       `json:"total"`
	Page      int       `json:"page"`
	PerPage   int       `json:"per_page"`
	PageCount int       `json:"page_count"`
	HasMore   bool      `json:"has_more"`
	Truncated bool      `json:"truncated,omitempty"`
	Messages  []Message `json:"messages"`
}

// User is get_user's result. No email: users:read does not grant it.
type User struct {
	ID           string `json:"id"`
	TeamID       string `json:"team_id,omitempty"`
	Name         string `json:"name"`
	RealName     string `json:"real_name,omitempty"`
	DisplayName  string `json:"display_name,omitempty"`
	Title        string `json:"title,omitempty"`
	TZ           string `json:"tz,omitempty"`
	StatusText   string `json:"status_text,omitempty"`
	StatusEmoji  string `json:"status_emoji,omitempty"`
	AvatarURL    string `json:"avatar_url,omitempty"`
	IsBot        bool   `json:"is_bot"`
	IsAdmin      bool   `json:"is_admin"`
	IsOwner      bool   `json:"is_owner,omitempty"`
	IsRestricted bool   `json:"is_restricted,omitempty"`
	Deleted      bool   `json:"deleted"`
}

// PostedMessage is post_message's and reply_in_thread's result: the
// identifiers of the new message, never its text.
type PostedMessage struct {
	Channel  string `json:"channel"`
	TS       string `json:"ts"`
	ThreadTS string `json:"thread_ts,omitempty"`
}

// AddedReaction is add_reaction's result. AlreadyReacted says Slack
// reported the reaction was already there (the desired state holds).
type AddedReaction struct {
	Channel        string `json:"channel"`
	Timestamp      string `json:"timestamp"`
	Name           string `json:"name"`
	AlreadyReacted bool   `json:"already_reacted,omitempty"`
}

func toChannel(ch goslack.Channel) Channel {
	return Channel{
		ID: ch.ID, Name: ch.Name, IsPrivate: ch.IsPrivate, IsArchived: ch.IsArchived, IsMember: ch.IsMember,
		NumMembers: ch.NumMembers, Topic: ch.Topic.Value, Purpose: ch.Purpose.Value, Created: unixTime(int64(ch.Created)),
	}
}

func toMessage(m goslack.Message) Message {
	out := Message{
		TS: m.Timestamp, ThreadTS: m.ThreadTimestamp, User: m.User, Username: m.Username, BotID: m.BotID, Text: m.Text,
		Subtype: m.SubType, ReplyCount: m.ReplyCount, Edited: m.Edited != nil, FileCount: len(m.Files), Time: tsTime(m.Timestamp),
	}
	if out.Text == "" && len(m.Files) > 0 {
		out.Text = "(file upload)"
	}
	for _, r := range m.Reactions {
		out.Reactions = append(out.Reactions, Reaction{Name: r.Name, Count: r.Count})
	}
	return out
}

func toSearchMessage(m goslack.SearchMessage) Message {
	return Message{
		TS: m.Timestamp, ThreadTS: threadTSFromPermalink(m.Permalink), User: m.User, Username: m.Username, Text: m.Text,
		Channel: m.Channel.ID, ChannelName: m.Channel.Name, Permalink: m.Permalink, Time: tsTime(m.Timestamp),
	}
}

func toUser(u *goslack.User) User {
	return User{
		ID: u.ID, TeamID: u.TeamID, Name: u.Name, RealName: u.RealName, DisplayName: u.Profile.DisplayName, Title: u.Profile.Title,
		TZ: u.TZ, StatusText: u.Profile.StatusText, StatusEmoji: u.Profile.StatusEmoji, AvatarURL: u.Profile.Image72,
		IsBot: u.IsBot, IsAdmin: u.IsAdmin, IsOwner: u.IsOwner, IsRestricted: u.IsRestricted, Deleted: u.Deleted,
	}
}

// threadTSFromPermalink reads the thread_ts query parameter of a search
// hit's permalink (the search API does not report it otherwise).
func threadTSFromPermalink(permalink string) string {
	u, err := url.Parse(permalink)
	if err != nil {
		return ""
	}
	return u.Query().Get("thread_ts")
}

// tsTime renders a Slack ts ("1700002000.000100") as RFC 3339 UTC.
func tsTime(ts string) string {
	t, ok := parseTS(ts)
	if !ok {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func unixTime(sec int64) string {
	if sec <= 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

// encodedSize is the serialised size of v, the measure the bounds apply to.
func encodedSize(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return len(b)
}
