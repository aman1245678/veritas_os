"""Durable single-use signed-IAM reconciliation challenge.

Revision ID: 0011
Revises: 0010

Opt-in synthetic IAM challenge registry. It never grants execution authority.
Rows are retained to reject replay after process restart.
"""
from alembic import op
import sqlalchemy as sa

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "iam_reconciliation_challenges",
        sa.Column("challenge_sha256", sa.Text(), primary_key=True),
        sa.Column("operation_id", sa.Text(), nullable=False),
        sa.Column("authorization_id", sa.Text(), nullable=False),
        sa.Column("consumption_id", sa.Text(), nullable=False),
        sa.Column("permit_id", sa.Text(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evidence_hash", sa.Text(), nullable=True),
        sa.CheckConstraint("state IN ('ISSUED', 'CONSUMED')",
                           name="iam_challenge_valid_state"),
        sa.CheckConstraint(
            "(state='ISSUED' AND consumed_at IS NULL AND evidence_hash IS NULL) OR "
            "(state='CONSUMED' AND consumed_at IS NOT NULL AND evidence_hash IS NOT NULL)",
            name="iam_challenge_consumption_shape"),
        sa.CheckConstraint("expires_at > issued_at AND expires_at <= issued_at + INTERVAL '120 seconds'",
                           name="iam_challenge_lifetime"),
        sa.CheckConstraint("challenge_sha256 ~ '^[0-9a-f]{64}$'",
                           name="iam_challenge_digest_shape"),
        sa.ForeignKeyConstraint(["operation_id"], ["bind_effect_states.operation_id"]),
    )
    op.create_index(
        "iam_challenge_one_consumed_per_operation",
        "iam_reconciliation_challenges", ["operation_id"], unique=True,
        postgresql_where=sa.text("state = 'CONSUMED'"),
    )


def downgrade() -> None:
    # Downgrade is destructive and must not be performed on authoritative data.
    # Migrations are intended for disposable synthetic fixtures only here.
    op.drop_index("iam_challenge_one_consumed_per_operation",
                  table_name="iam_reconciliation_challenges")
    op.drop_table("iam_reconciliation_challenges")
