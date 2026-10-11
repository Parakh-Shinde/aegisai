"""Add encrypted MFA factors and scoped API-token identities.

Revision ID: 0016_mfa_api_tokens
Revises: 0015_identity_ops
Create Date: 2026-10-11
"""

import sqlalchemy as sa
from alembic import op

revision = "0016_mfa_api_tokens"
down_revision = "0015_identity_ops"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("mfa_secret_encrypted", sa.Text(), nullable=True))
    op.add_column(
        "users",
        sa.Column("mfa_pending_secret_encrypted", sa.Text(), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("mfa_pending_created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column(
            "mfa_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "users",
        sa.Column("mfa_enrolled_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.alter_column("users", "mfa_enabled", server_default=None)

    api_token_role = sa.Enum(
        "admin",
        "security_analyst",
        "viewer",
        name="api_token_role",
        native_enum=False,
    )
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("token_prefix", sa.String(length=24), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("role", api_token_role, nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash", name="uq_api_tokens_token_hash"),
        sa.UniqueConstraint("organization_id", "name", name="uq_api_tokens_org_name"),
    )
    op.create_index("ix_api_tokens_organization_id", "api_tokens", ["organization_id"])
    op.create_index("ix_api_tokens_token_prefix", "api_tokens", ["token_prefix"])


def downgrade() -> None:
    op.drop_index("ix_api_tokens_token_prefix", table_name="api_tokens")
    op.drop_index("ix_api_tokens_organization_id", table_name="api_tokens")
    op.drop_table("api_tokens")
    op.drop_column("users", "mfa_enrolled_at")
    op.drop_column("users", "mfa_enabled")
    op.drop_column("users", "mfa_pending_created_at")
    op.drop_column("users", "mfa_pending_secret_encrypted")
    op.drop_column("users", "mfa_secret_encrypted")
