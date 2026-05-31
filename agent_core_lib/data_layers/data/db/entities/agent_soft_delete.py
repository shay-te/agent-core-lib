# agent_import

from core_lib.data_layers.data.db.sqlalchemy.base import Base
from core_lib.data_layers.data.db.sqlalchemy.mixins.soft_delete_mixin import SoftDeleteMixin


class Agent(Base, SoftDeleteMixin):
    __tablename__ = 'agent'

    # agent_column
