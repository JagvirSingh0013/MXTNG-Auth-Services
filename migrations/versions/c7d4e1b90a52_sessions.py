"""sessions: one live session per credential

Revision ID: c7d4e1b90a52
Revises: b3f1a92c77de
Create Date: 2026-08-19
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c7d4e1b90a52"
down_revision: Union[str, None] = "b3f1a92c77de"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("session_id", sa.String(length=36), nullable=False),
        sa.Column("credential_id", sa.Integer(), nullable=False),
        sa.Column("audience", sa.String(length=64), nullable=False),
        sa.Column("family_id", sa.String(length=36), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("revoked_reason", sa.String(length=32), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["credential_id"], ["credentials.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("sessions", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_sessions_session_id"), ["session_id"], unique=True)
        batch_op.create_index(batch_op.f("ix_sessions_credential_id"), ["credential_id"])
        batch_op.create_index(batch_op.f("ix_sessions_family_id"), ["family_id"])


def downgrade() -> None:
    with op.batch_alter_table("sessions", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_sessions_family_id"))
        batch_op.drop_index(batch_op.f("ix_sessions_credential_id"))
        batch_op.drop_index(batch_op.f("ix_sessions_session_id"))
    op.drop_table("sessions")
