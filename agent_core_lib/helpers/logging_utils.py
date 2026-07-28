from __future__ import annotations

import logging


_BASE_LOGGER_NAME = 'agent_core_lib'


def configure_logger(name: str) -> logging.Logger:
    suffix = str(name or '').strip()
    if suffix:
        return logging.getLogger(f'{_BASE_LOGGER_NAME}.{suffix}')
    return logging.getLogger(_BASE_LOGGER_NAME)
