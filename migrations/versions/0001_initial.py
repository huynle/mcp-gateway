"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-06-08 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("is_admin", sa.Boolean(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("token_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("token_last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("external_id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(op.f("ix_users_external_id"), "users", ["external_id"], unique=False)
    op.create_index(op.f("ix_users_token_hash"), "users", ["token_hash"], unique=False)

    op.create_table(
        "mcp_servers",
        sa.Column("slug", sa.String(length=80), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("transport", sa.String(length=50), nullable=False),
        sa.Column("first_party", sa.Boolean(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("credential_header_map", sa.JSON(), nullable=False),
        sa.Column("tool_cache", sa.JSON(), nullable=True),
        sa.Column("tool_cache_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("slug"),
    )

    op.create_table(
        "access_grants",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("server_slug", sa.String(length=80), nullable=False),
        sa.Column("tool_name", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["server_slug"], ["mcp_servers.slug"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "server_slug", "tool_name", name="uq_grant_user_server_tool"),
    )
    op.create_index("ix_grant_lookup", "access_grants", ["user_id", "server_slug", "tool_name"], unique=False)

    op.create_table(
        "user_credentials",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("server_slug", sa.String(length=80), nullable=False),
        sa.Column("encrypted_config", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["server_slug"], ["mcp_servers.slug"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "server_slug", name="uq_credential_user_server"),
    )
    op.create_index(op.f("ix_user_credentials_server_slug"), "user_credentials", ["server_slug"], unique=False)
    op.create_index(op.f("ix_user_credentials_user_id"), "user_credentials", ["user_id"], unique=False)

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=True),
        sa.Column("server_slug", sa.String(length=80), nullable=True),
        sa.Column("tool_name", sa.String(length=255), nullable=True),
        sa.Column("method", sa.String(length=80), nullable=False),
        sa.Column("allowed", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_server_tool_time", "audit_logs", ["server_slug", "tool_name", "created_at"], unique=False)
    op.create_index("ix_audit_user_time", "audit_logs", ["user_id", "created_at"], unique=False)
    op.create_index(op.f("ix_audit_logs_request_id"), "audit_logs", ["request_id"], unique=False)
    op.create_index(op.f("ix_audit_logs_user_id"), "audit_logs", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_audit_logs_user_id"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_request_id"), table_name="audit_logs")
    op.drop_index("ix_audit_user_time", table_name="audit_logs")
    op.drop_index("ix_audit_server_tool_time", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index(op.f("ix_user_credentials_user_id"), table_name="user_credentials")
    op.drop_index(op.f("ix_user_credentials_server_slug"), table_name="user_credentials")
    op.drop_table("user_credentials")
    op.drop_index("ix_grant_lookup", table_name="access_grants")
    op.drop_table("access_grants")
    op.drop_table("mcp_servers")
    op.drop_index(op.f("ix_users_token_hash"), table_name="users")
    op.drop_index(op.f("ix_users_external_id"), table_name="users")
    op.drop_table("users")
