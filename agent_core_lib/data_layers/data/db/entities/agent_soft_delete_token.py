# agent_import

from core_lib.data_layers.data.db.sqlalchemy.base import Base
from core_lib.data_layers.data.db.sqlalchemy.mixins.soft_delete_mixin import SoftDeleteMixin
from core_lib.data_layers.data.db.sqlalchemy.mixins.soft_delete_token_mixin import SoftDeleteTokenMixin


class Agent(Base, SoftDeleteMixin, SoftDeleteTokenMixin):
    __tablename__ = 'agent'

    # agent_column
