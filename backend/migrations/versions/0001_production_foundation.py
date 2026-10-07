"""Add organizations, authentication, tenant-scoped records, and audit logs.

Revision ID: 0001_production_foundation
Revises:
Create Date: 2026-10-07
"""

import sqlalchemy as sa
from alembic import op

revision = "0001_production_foundation"
down_revision = None
branch_labels = None
depends_on = None


user_role = sa.Enum(
    "admin",
    "security_analyst",
    "viewer",
    name="user_role",
    native_enum=False,
)


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("slug", sa.String(length=80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("slug"),
    )
    op.create_index("ix_organizations_slug", "organizations", ["slug"])

    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("role", user_role, nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_users_organization_id", "users", ["organization_id"])
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "registered_models",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("model_id", sa.String(length=256), nullable=False),
        sa.Column("provider", sa.String(length=80), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("version", sa.String(length=120), nullable=False),
        sa.Column("endpoint", sa.String(length=512), nullable=False),
        sa.Column("deployment_type", sa.String(length=80), nullable=False),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("authentication", sa.String(length=80), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.UniqueConstraint(
            "organization_id", "model_id", name="uq_registered_models_org_model"
        ),
    )
    op.create_index(
        "ix_registered_models_organization_id", "registered_models", ["organization_id"]
    )

    op.create_table(
        "security_test_results",
        sa.Column("test_id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("test_type", sa.String(), nullable=False),
        sa.Column("test_category", sa.String(), nullable=False),
        sa.Column("model", sa.String(), nullable=False),
        sa.Column("risk_status", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column("finding", sa.Text(), nullable=False),
        sa.Column("prompt_sent", sa.Text(), nullable=False),
        sa.Column("model_response", sa.Text(), nullable=False),
        sa.Column("campaign_id", sa.String(), nullable=True),
        sa.Column("review_status", sa.String(length=32), nullable=False),
        sa.Column("review_notes", sa.Text(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by_user_id", sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["reviewed_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
    )
    for column in (
        "test_id",
        "organization_id",
        "test_type",
        "test_category",
        "model",
        "risk_status",
        "severity",
        "campaign_id",
        "review_status",
    ):
        op.create_index(
            f"ix_security_test_results_{column}", "security_test_results", [column]
        )

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("actor_id", sa.String(length=36), nullable=True),
        sa.Column("action", sa.String(length=120), nullable=False),
        sa.Column("resource_type", sa.String(length=120), nullable=False),
        sa.Column("resource_id", sa.String(length=128), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("entry_hash"),
    )
    op.create_index("ix_audit_logs_organization_id", "audit_logs", ["organization_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("security_test_results")
    op.drop_table("registered_models")
    op.drop_table("users")
    op.drop_table("organizations")
