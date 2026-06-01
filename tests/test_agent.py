import unittest
# agent_core_lib_import
# agent_test_imports
from core_lib.helpers.test import load_core_lib_config
# agent_sync_create_core_lib_import


class TestAgent(unittest.TestCase):
    def setUpClass(self):
        self.agent_snake_core_lib = sync_create_start_core_lib()


# agent_test_functions
