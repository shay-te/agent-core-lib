# AGENTS Notes

## Workspace-wide coding convention (non-negotiable)

**Every Python method that reads fields out of a config or a raw response object follows fetch → validate → use, in that order, with no fallback defaults and no aliases.** See the "Coding conventions (workspace-wide, all Python repos)" section in `architecture.md` — the canonical examples are the three `*ConnectionFactory.__init__` methods in `llm-core-lib/llm_core_lib/connections/` and their `_invoke` / `_invoke_chat` / `_extract_text` / `embed` response-parsing methods.

Concretely: no `config.get('region', 'us-east-1')` inline defaults, no `model_id or model` alias chains, no `getattr(block, 'text', '') or ''` inside generator expressions or final returns. Pull every field into a named local at the top, validate / normalize next, then use the named locals.

Inside this repo the rule applies to:

- **`agent_core_lib/client/agent_client_factory.py`** — both Claude and OpenHands config-builders. Every `getattr(cli_cfg, 'binary', '') or ''`-style call inside the dict literal must be hoisted into a named fetch local, validated, then dropped into the dataclass / dict in the use block.
- **`agent_core_lib/helpers/agent_prompt_utils.py`** — every function that builds a prompt string from a `task` / `prepared_task` / `comment` / `repository` object. Pull `branch_name = getattr(task, 'branch_name', '')`, `repository_branches = getattr(task, 'repository_branches', {}) or {}`, etc. into a fetch block at the top of the function, not inline at the call site.
- **`agent_core_lib/helpers/session_id_utils.py`** — same for the `getattr(obj, AGENT_SESSION_ID, '')` / `payload.get(AGENT_SESSION_ID)` chains.
- **`agent_core_lib/helpers/resume_prompt_utils.py`** — same for the per-event `getattr(event, 'event_type', '')` / `getattr(event, 'raw', {})` extractions.
- **`agent_core_lib/helpers/result_utils.py`** — even the small `payload.get(ImplementationFields.SUCCESS, default)` site at the top of a function is fine; the rule kicks in the moment a second `.get(...)` joins the body.

Variable names: spell out what the value is. No `cfg`, `ws`, `bf`, `s`, `c`, `d`, `r` shorthand. `claude_config`, `workspace`, `bedrock_factory`, `service`, `collection`, `document` instead. See the matching rule in `library-core-lib/AGENTS.md` for the full list.
