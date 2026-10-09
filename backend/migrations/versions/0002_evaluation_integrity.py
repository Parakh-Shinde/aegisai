"""Add corpus provenance and saved evaluation baselines.

Revision ID: 0002_evaluation_integrity
Revises: 0001_production_foundation
Create Date: 2026-10-08
"""

import sqlalchemy as sa
from alembic import op

revision = "0002_evaluation_integrity"
down_revision = "0001_production_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "security_test_results",
        sa.Column("corpus_suite_name", sa.String(length=120), nullable=True),
    )
    op.add_column(
        "security_test_results",
        sa.Column("corpus_version", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "security_test_results",
        sa.Column("corpus_digest", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "security_test_results",
        sa.Column("scoring_rule_version", sa.String(length=64), nullable=True),
    )
    op.create_index(
        "ix_security_test_results_corpus_digest",
        "security_test_results",
        ["corpus_digest"],
    )

    op.create_table(
        "evaluation_baselines",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("source_campaign_id", sa.String(length=128), nullable=False),
        sa.Column("model", sa.String(length=256), nullable=False),
        sa.Column("corpus_suite_name", sa.String(length=120), nullable=False),
        sa.Column("corpus_version", sa.String(length=64), nullable=False),
        sa.Column("corpus_digest", sa.String(length=64), nullable=False),
        sa.Column("scoring_rule_version", sa.String(length=64), nullable=False),
        sa.Column("total_tests", sa.Integer(), nullable=False),
        sa.Column("safety_score", sa.Integer(), nullable=False),
        sa.Column("leaked_tests", sa.Integer(), nullable=False),
        sa.Column("uncertain_tests", sa.Integer(), nullable=False),
        sa.Column("high_risk_tests", sa.Integer(), nullable=False),
        sa.Column("evidence_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint(
            "organization_id",
            "name",
            name="uq_evaluation_baselines_org_name",
        ),
    )
    op.create_index(
        "ix_evaluation_baselines_organization_id",
        "evaluation_baselines",
        ["organization_id"],
    )


def downgrade() -> None:
    op.drop_table("evaluation_baselines")
    op.drop_index(
        "ix_security_test_results_corpus_digest",
        table_name="security_test_results",
    )
    op.drop_column("security_test_results", "scoring_rule_version")
    op.drop_column("security_test_results", "corpus_digest")
    op.drop_column("security_test_results", "corpus_version")
    op.drop_column("security_test_results", "corpus_suite_name")
