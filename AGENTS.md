# AGENTS Notes — agent-core-lib

## Built on core-lib — read its rulebook first

This library is a `*-core-lib`. The shared architecture, conventions, and
scaffolding are **not** repeated here — they live in the `core-lib` package
(the `../core-lib/` checkout beside this repo, or the installed `core-lib`):

| Read | For |
|---|---|
| `core-lib/AGENTS.md` | **Read first.** The AGNOSTIC principles, then the canonical recipe (§0–§17): naming, folder tree, config, entities, DataAccess, services, composition root, observers, jobs, migrations, tests, build order, things to avoid, final checklist. |
| `core-lib/skills/` | Copy-paste scaffolding templates, one per core-lib part. |

**MANDATORY — before you create or modify any part below, first load the
matching core-lib skill** (open and follow it). This is a hard rule: match the
row and load the skill *before* writing code. Never write core-lib code from
memory when a matching skill exists.

| If you are about to… | You MUST first load |
|---|---|
| add or change an entity / table / model / column / nested enum | [`core-lib-entity`](../core-lib/skills/core-lib-entity/SKILL.md) |
| add or change a DataAccess / DAO / repository / query / get_by / list | [`core-lib-data-access`](../core-lib/skills/core-lib-data-access/SKILL.md) |
| add or change a Service / business logic / public method / caching | [`core-lib-service`](../core-lib/skills/core-lib-service/SKILL.md) |
| add or change an external client / provider / SDK / connection factory | [`core-lib-connection`](../core-lib/skills/core-lib-connection/SKILL.md) |
| add a migration / alter / create / drop a table, column, index, constraint | [`core-lib-migration`](../core-lib/skills/core-lib-migration/SKILL.md) |
| add / fix / restructure tests or raise coverage | [`core-lib-tests`](../core-lib/skills/core-lib-tests/SKILL.md) |

Everything below this line is **agent-core-lib-specific** — lessons that apply only to
this library. Anything generic belongs in `core-lib/AGENTS.md` instead, so every
core-lib inherits it.

---

## Where fetch → validate → use bites in this repo

The rule itself is core-lib **§1.1**. These are the call sites in this repo that
most often violate it — check them first:

- **`agent_core_lib/client/agent_client_factory.py`** — both Claude and OpenHands config-builders. Every `getattr(cli_cfg, 'binary', '') or ''`-style call inside the dict literal must be hoisted into a named fetch local, validated, then dropped into the dataclass / dict in the use block.
- **`agent_core_lib/helpers/agent_prompt_utils.py`** — every function that builds a prompt string from a `task` / `prepared_task` / `comment` / `repository` object. Pull `branch_name = getattr(task, 'branch_name', '')`, `repository_branches = getattr(task, 'repository_branches', {}) or {}`, etc. into a fetch block at the top of the function, not inline at the call site.
- **`agent_core_lib/helpers/session_id_utils.py`** — same for the `getattr(obj, AGENT_SESSION_ID, '')` / `payload.get(AGENT_SESSION_ID)` chains.
- **`agent_core_lib/helpers/resume_prompt_utils.py`** — same for the per-event `getattr(event, 'event_type', '')` / `getattr(event, 'raw', {})` extractions.
- **`agent_core_lib/helpers/result_utils.py`** — even the small `payload.get(ImplementationFields.SUCCESS, default)` site at the top of a function is fine; the rule kicks in the moment a second `.get(...)` joins the body.

In this repo that means `claude_config`, `workspace`, `bedrock_factory` — not
`cfg`, `ws`, `bf` (core-lib §1.2).

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

## Testing in this repo

The rules are core-lib **§7.1** (one `TestCase` per file) and **§7.2** (real
collaborators, mock only true boundaries). Repo-specific application:

- Tests live under `agent_core_lib/tests/`. Shared fakes (a logger spy, a
  synthetic task, a config builder) go in a sibling `<topic>_helpers.py`.
- The SUT's direct collaborators here are the pure-Python helpers in
  `helpers/` — wire the real types. `mock.Mock(spec=...)` of one is a smell.
- **Legitimate mock surfaces in this repo:** the logger (for assertion, not
  isolation), the filesystem when destructive (use `tempfile`), and outbound
  subprocess / SDK calls — Claude CLI / Codex CLI / OpenHands worker, for which
  `MockClaudeClient` and friends are the established pattern.
- PII and credential-detection tests are **not** here — they moved to
  `pii-core-lib/pii_core_lib/tests/` when that package was extracted.
