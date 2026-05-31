from core_lib.web_helpers.web_helprs_utils import WebHelpersUtils
# agent_core_lib_import


class AgentCoreLibInstance(object):
    _app_instance = None

    @staticmethod
    def init(core_lib_cfg):
        if not AgentCoreLibInstance._app_instance:
            # WebHelpersUtils.init(WebHelpersUtils.ServerType.FLASK) #TODO: initilazie the correct server type
            AgentCoreLibInstance._app_instance = AgentCoreLibClass(core_lib_cfg)

    @staticmethod
    def get() -> AgentCoreLibClass:
        return AgentCoreLibInstance._app_instance
