"""Allow NULL for sender_id in LetterBlock

Revision ID: 3d96f39fae22
Revises: e1f5ef87cf46
Create Date: 2025-04-27 17:53:12.399970

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3d96f39fae22'
down_revision = 'e1f5ef87cf46'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('letter_block', schema=None) as batch_op:
        batch_op.alter_column('sender_id',
               existing_type=sa.INTEGER(),
               nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('letter_block', schema=None) as batch_op:
        batch_op.alter_column('sender_id',
               existing_type=sa.INTEGER(),
               nullable=False)

    # ### end Alembic commands ###
