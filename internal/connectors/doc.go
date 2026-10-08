// Package connectors owns the connector interface and the in-process
// connectors (fake, github, slack, atlassian, google, microsoft). Each tool
// declares name, description, input schema, read/write, required scopes,
// resource-identity extraction and, for writes, how it can be reconciled. The
// gateway injects the account and approval_id arguments; connectors never see
// them. The fake connector ships first and backs every pipeline test.
//
// Design: Brain plan 36bakiw8 section 5; decisions bt8ukyrd, 0sod196t.
package connectors
