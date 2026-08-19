"""sign-in challenges replace oauth exchange codes (ADR-0011)

Revision ID: b3f1a92c77de
Revises: d78048847fb2
Create Date: 2026-08-19
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b3f1a92c77de"
down_revision: Union[str, None] = "d78048847fb2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sign_in_challenges",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("challenge_id", sa.String(length=64), nullable=False),
        sa.Column("credential_id", sa.Integer(), nullable=False),
        sa.Column("code_hash", sa.String(length=255), nullable=False),
        sa.Column("audience", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("sends", sa.Integer(), nullable=False),
        sa.Column("last_sent_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["credential_id"], ["credentials.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("sign_in_challenges", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_sign_in_challenges_challenge_id"), ["challenge_id"], unique=True
        )
        batch_op.create_index(
            batch_op.f("ix_sign_in_challenges_credential_id"), ["credential_id"], unique=False
        )

    # The challenge id supersedes the Google hand-off: it is useless without the
    # emailed code, so it can ride in a redirect URL where a token could not.
    op.drop_table("oauth_exchange_codes")


def downgrade() -> None:
    op.create_table(
        "oauth_exchange_codes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("credential_id", sa.Integer(), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("audience", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["credential_id"], ["credentials.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("oauth_exchange_codes", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_oauth_exchange_codes_code_hash"), ["code_hash"], unique=True
        )
        batch_op.create_index(
            batch_op.f("ix_oauth_exchange_codes_credential_id"), ["credential_id"], unique=False
        )

    with op.batch_alter_table("sign_in_challenges", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_sign_in_challenges_credential_id"))
        batch_op.drop_index(batch_op.f("ix_sign_in_challenges_challenge_id"))
    op.drop_table("sign_in_challenges")
