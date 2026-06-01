"""Build the configured agent backend.

Takes config + an ``AgentPlatform`` selector, returns something that
satisfies ``agent_provider_contracts.AgentProvider``.

The factory keeps the runtime knobs (``docker_mode_on``,
``read_only_tools_on``, ``testing``) explicit rather than burying
them in config because each one materially changes how the
backend behaves at spawn time and operators have been bitten by
silent config inheritance there before.
"""

from __future__ import annotations

from typing import Any

from agent_provider_contracts.agent_provider_contracts.agent_provider import (
    AgentProvider,
)

from agent_core_lib.agent_core_lib.platform import AgentPlatform


# Aliases the operator can write in the agent_backend config field that
# resolve to canonical platforms. Centralised here so a future
# alias rename lands in one place rather than scattered string
# checks across the codebase.
_PLATFORM_ALIASES: dict[str, AgentPlatform] = {
    'claude': AgentPlatform.CLAUDE,
    'claude-code': AgentPlatform.CLAUDE,
    'claude_code': AgentPlatform.CLAUDE,
    'claude-cli': AgentPlatform.CLAUDE,
    'claude_cli': AgentPlatform.CLAUDE,
    'codex': AgentPlatform.CODEX,
    'codex-cli': AgentPlatform.CODEX,
    'codex_cli': AgentPlatform.CODEX,
    'openai-codex': AgentPlatform.CODEX,
    'openai_codex': AgentPlatform.CODEX,
    'openhands': AgentPlatform.OPENHANDS,
    'open-hands': AgentPlatform.OPENHANDS,
    'open_hands': AgentPlatform.OPENHANDS,
    '': AgentPlatform.OPENHANDS,  # historical default
}


def resolve_platform(name: str) -> AgentPlatform:
    """Map an operator-supplied agent backend name to an ``AgentPlatform`` enum."""
    key = (name or '').strip().lower()
    if key not in _PLATFORM_ALIASES:
        raise ValueError(
            f'unsupported agent backend: {name!r}; '
            f'supported values: {sorted({p.value for p in AgentPlatform})}'
        )
    return _PLATFORM_ALIASES[key]


class AgentClientFactory(object):
    """Construct the configured ``AgentProvider`` implementation.

    Lazy on imports — the Claude impl pulls in the streaming
    session machinery, the OpenHands impl pulls in the HTTP
    client. Importing only the one we need keeps the boot of an
    OpenHands-only install free of Claude's transitive
    dependencies (and vice versa).
    """

    def __init__(
        self,
        *,
        max_retries: int,
        testing: bool = False,
        docker_mode_on: bool = False,
        read_only_tools_on: bool = False,
        workspace_refusal_guidance: str = '',
    ) -> None:
        self._max_retries = max_retries
        self._testing = testing
        self._docker_mode_on = docker_mode_on
        self._read_only_tools_on = read_only_tools_on
        # Product-specific refusal guidance the host application wants
        # appended to the generic workspace scope block. Passed only to
        # the Claude client; '' for any consumer that doesn't set it, so
        # codex/openhands defaults are unchanged.
        self._workspace_refusal_guidance = workspace_refusal_guidance or ''

    def build(self, platform: AgentPlatform, cfg: Any) -> AgentProvider:
        if platform == AgentPlatform.CLAUDE:
            return self._build_claude(cfg)
        if platform == AgentPlatform.CODEX:
            return self._build_codex(cfg)
        if platform == AgentPlatform.OPENHANDS:
            return self._build_openhands(cfg)
        raise ValueError(f'unhandled agent platform: {platform!r}')

    def _build_claude(self, open_cfg: Any) -> AgentProvider:
        # Imported lazily so an OpenHands-only install never
        # touches the Claude streaming machinery.
        from claude_core_lib.claude_core_lib.cli_client import ClaudeCliClient

        return self._build_cli_agent(
            open_cfg, config_key='claude', client_cls=ClaudeCliClient,
        )

    def _build_codex(self, open_cfg: Any) -> AgentProvider:
        # Imported lazily so a Claude-only / OpenHands-only install
        # never touches the Codex module tree.
        from codex_core_lib.codex_core_lib.cli_client import CodexCliClient

        return self._build_cli_agent(
            open_cfg, config_key='codex', client_cls=CodexCliClient,
        )

    def _build_cli_agent(
        self, open_cfg: Any, *, config_key: str, client_cls,
    ) -> AgentProvider:
        # 1. fetch — pull the CLI sub-config + every field we'll touch
        # on it into named locals up front. Same rule as the LLM
        # connection factories.
        cli_cfg = getattr(open_cfg, config_key, None)
        repository_root_path_raw = getattr(open_cfg, 'repository_root_path', '')

        # 2. validate — the CLI block must be present; everything else
        # we normalize below.
        if cli_cfg is None:
            raise RuntimeError(
                f'agent_backend={config_key} requires a {config_key} configuration block; '
                'rebuild the configuration template'
            )

        # Now that cli_cfg is known to exist, fetch every field off it.
        binary_raw = getattr(cli_cfg, 'binary', '')
        model_raw = getattr(cli_cfg, 'model', '')
        max_turns = getattr(cli_cfg, 'max_turns', None)
        effort_raw = getattr(cli_cfg, 'effort', '')
        allowed_tools_raw = getattr(cli_cfg, 'allowed_tools', '')
        disallowed_tools_raw = getattr(cli_cfg, 'disallowed_tools', '')
        bypass_permissions_raw = getattr(cli_cfg, 'bypass_permissions', False)
        timeout_seconds_raw = getattr(cli_cfg, 'timeout_seconds', 1800)
        model_smoke_test_enabled_raw = getattr(
            cli_cfg, 'model_smoke_test_enabled', False
        )
        architecture_doc_path_raw = getattr(cli_cfg, 'architecture_doc_path', '')
        lessons_path_raw = getattr(cli_cfg, 'lessons_path', '')

        # 2b. normalize — coerce to the types the client constructor
        # expects, mostly "string-or-empty".
        repository_root_path = str(repository_root_path_raw or '').strip()
        binary = str(binary_raw or '')
        model = str(model_raw or '')
        effort = str(effort_raw or '')
        allowed_tools = str(allowed_tools_raw or '')
        disallowed_tools = str(disallowed_tools_raw or '')
        bypass_permissions = bool(bypass_permissions_raw)
        timeout_seconds = int(timeout_seconds_raw or 1800)
        model_smoke_test_enabled = (
            not self._testing and bool(model_smoke_test_enabled_raw)
        )
        architecture_doc_path = str(architecture_doc_path_raw or '')
        lessons_path = str(lessons_path_raw or '')

        # 3. use — feed only named, already-normalized locals into the
        # client constructor.
        return client_cls(
            binary=binary,
            model=model,
            max_turns=max_turns,
            effort=effort,
            allowed_tools=allowed_tools,
            disallowed_tools=disallowed_tools,
            bypass_permissions=bypass_permissions,
            docker_mode_on=self._docker_mode_on,
            read_only_tools_on=self._read_only_tools_on,
            timeout_seconds=timeout_seconds,
            max_retries=self._max_retries,
            repository_root_path=repository_root_path,
            model_smoke_test_enabled=model_smoke_test_enabled,
            architecture_doc_path=architecture_doc_path,
            lessons_path=lessons_path,
            # Product-specific refusal guidance the spawner threads in;
            # every CLI agent (Claude, Codex) receives it identically so
            # the boundary block is consistent across backends.
            workspace_refusal_guidance=self._workspace_refusal_guidance,
        )

    def _build_openhands(self, open_cfg: Any) -> AgentProvider:
        # Imported lazily — see _build_claude for the rationale.
        from openhands_core_lib.openhands_core_lib.openhands_client import OpenHandsClient
        from openhands_core_lib.openhands_core_lib.config_utils import (
            resolved_openhands_base_url,
            resolved_openhands_llm_settings,
        )

        # 1. fetch — pull the openhands sub-config + every field we'll
        # touch on it into named locals up front.
        openhands_cfg = getattr(open_cfg, 'openhands', None)

        # 2. validate — the openhands block must be present.
        if openhands_cfg is None:
            raise RuntimeError(
                'agent_backend=openhands requires an openhands configuration block; '
                'rebuild the configuration template'
            )

        # Now that openhands_cfg exists, fetch every field off it.
        api_key = openhands_cfg.api_key
        poll_interval_seconds_raw = openhands_cfg.get('poll_interval_seconds', 2.0)
        max_poll_attempts_raw = openhands_cfg.get('max_poll_attempts', 900)
        model_smoke_test_enabled_raw = getattr(
            openhands_cfg, 'model_smoke_test_enabled', True
        )

        # 2b. normalize.
        base_url = resolved_openhands_base_url(openhands_cfg, testing=self._testing)
        llm_settings = resolved_openhands_llm_settings(
            openhands_cfg, testing=self._testing,
        )
        poll_interval_seconds = float(poll_interval_seconds_raw)
        max_poll_attempts = int(max_poll_attempts_raw)
        model_smoke_test_enabled = (
            not self._testing and bool(model_smoke_test_enabled_raw)
        )

        # 3. use.
        return OpenHandsClient(
            base_url,
            api_key,
            self._max_retries,
            llm_settings=llm_settings,
            poll_interval_seconds=poll_interval_seconds,
            max_poll_attempts=max_poll_attempts,
            model_smoke_test_enabled=model_smoke_test_enabled,
            workspace_refusal_guidance=self._workspace_refusal_guidance,
        )
