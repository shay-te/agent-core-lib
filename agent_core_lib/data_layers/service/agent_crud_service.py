from core_lib.data_layers.service.service import Service
from core_lib.data_transform.result_to_dict import ResultToDict
from core_lib_generator.agent_core_lib import AgentCRUDDataAccess


class AgentCrudService(Service):
    def __init__(self, agent_da: AgentCRUDDataAccess):
        self._agent_da = agent_da

    @ResultToDict()
    def get(self, id: int):
        return self._agent_da.get(id)

    def update(self, id: int, data: dict):
        self._agent_da.update(id, data)

    @ResultToDict()
    def create(self, data: dict):
        return self._agent_da.create(data)

    def delete(self, id: int):
        self._agent_da.delete(id)
