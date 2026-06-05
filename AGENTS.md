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

## `requirements.txt` carries `pydantic>=2.0`

`pydantic>=2.0` is this repo's direct runtime dependency. It exists
because `agent_core_lib/safety/llm_view.py` ships the canonical
Pydantic v2 `BaseModel` subclass with `ConfigDict(extra='forbid',
frozen=True)` — the concrete LLM-view base every tool author should
subclass. The transport-layer marker (the class the
`llm_core_lib.safety.payload_gate` gate `isinstance`-checks against)
is a plain Python class in `llm-core-lib`; the Pydantic-enforced
allowlist contract is an *agent-layer* concern and lives here. The
split keeps `llm-core-lib` a pure transport library (no Pydantic
import) and respects its boundary test (`test_boundary.py`) that
forbids `agent_core_lib` imports from that side.

## Test file organization — one TestCase per file, filename mirrors the class

**Every new test file owns exactly one `unittest.TestCase` subclass, and the filename is the snake_case form of that class name.** This is a workspace-wide rule — see the "Test file organization" sub-section of "Coding conventions (workspace-wide, all Python repos)" in `architecture.md` for the full rationale, the helper-module pattern, and the canonical examples.

Inside this repo: any new file under `agent_core_lib/tests/` follows the rule. Examples in workflow terms:
- New tests for a single behaviour of a helper (a prompt builder, a session-id util) → one file, one TestCase named for that behaviour.
- Shared fakes / fixtures (a logger spy, a synthetic task, a config builder) go in a sibling `<topic>_helpers.py` module (no `test_` prefix so the test runner skips it).
- PII tests no longer live here — they moved to `pii-core-lib/pii_core_lib/tests/` when the package was extracted. Credential-detection tests moved at the same time (the credential scanner is a sensitive-data detector and lives next to the PII patterns in `pii-core-lib`).

## Tests prefer real collaborators over mocks

**Mock at infrastructure boundaries, not at internal seams.** Workspace-wide rule — see the "Tests prefer real collaborators over mocks" sub-section of "Coding conventions (workspace-wide, all Python repos)" in `architecture.md` for the full rule, the "is this a useful test?" check, and the list of where mocks belong vs. where they don't.

Canonical example for the workspace-wide rule lives in `pii-core-lib/pii_core_lib/tests/test_credential_scan.py` (the credential / phishing scanner moved there with the rest of the sensitive-data detectors). The pattern still applies inside this repo for the remaining helper tests.

For new tests under `agent_core_lib/tests/`:
- The SUT's direct collaborators (the per-task helper functions in `helpers/`) are pure Python — wire the real types and pass real data through. `mock.Mock(spec=...)` of a pure-Python helper is a smell. (Sensitive-data collaborators — PII patterns, credential patterns — now live in `pii-core-lib`; the same rule applies there.)
- The legitimate mock surfaces here are the **logger**, the **filesystem when destructive** (use `tempfile`), and any **outbound subprocess / SDK call** (Claude CLI / Codex CLI / OpenHands worker — the existing `MockClaudeClient` etc. in this repo are the pattern). The logger mock is for assertion, not isolation; everything else is mocked because the boundary itself can't run in a unit test.
- Pre-existing tests with `MagicMock()` collaborators are **not** required to be rewritten — apply the rule forward, with new tests and any time you're materially rewriting an old one.
