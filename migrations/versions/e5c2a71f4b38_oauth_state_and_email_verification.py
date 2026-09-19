"""oauth_states + credentials.email_verified_at

Security remediation (SECURITY_AUDIT H-3, C-2).

`oauth_states` gives the Sign-in-with-Google handshake a real CSRF nonce: the
callback previously accepted any authorization code from anyone, because the
`state` it was handed was never stored and never checked.

`credentials.email_verified_at` records when a mailbox was last proved
reachable. Existing rows are backfilled to NULL rather than to "verified" —
nothing in the old flow established that fact, so claiming it retroactively
would defeat the point.

Revision ID: e5c2a71f4b38
Revises: c7d4e1b90a52
Create Date: 2026-09-19
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "e5c2a71f4b38"
down_revision: Union[str, None] = "c7d4e1b90a52"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "oauth_states",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("state_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_oauth_states_state_hash"), "oauth_states", ["state_hash"], unique=True
    )
    # Lets the housekeeping sweep drop finished nonces without a table scan.
    op.create_index(op.f("ix_oauth_states_expires_at"), "oauth_states", ["expires_at"])

    op.add_column(
        "credentials",
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("credentials", "email_verified_at")
    op.drop_index(op.f("ix_oauth_states_expires_at"), table_name="oauth_states")
    op.drop_index(op.f("ix_oauth_states_state_hash"), table_name="oauth_states")
    op.drop_table("oauth_states")
