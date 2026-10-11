"""Add token-versioning support for identity lifecycle operations.

Revision ID: 0015_identity_ops
Revises: 0014_release_approvals
Create Date: 2026-10-11
"""

import sqlalchemy as sa
from alembic import op

revision = "0015_identity_ops"
down_revision = "0014_release_approvals"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("auth_epoch", sa.Integer(), nullable=False, server_default="0"),
    )
    op.alter_column("users", "auth_epoch", server_default=None)


def downgrade() -> None:
    op.drop_column("users", "auth_epoch")
