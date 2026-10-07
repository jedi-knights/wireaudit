# wireaudit

Go CLI that probes a live HTTP/HTTPS API and reports protocol-conformance findings (Must Fix / Should Fix / Consider). Single static binary, no runtime deps.

## Commands

```bash
make check   # fmt-check, build, vet, test, lint — run before every PR
make smoke   # probe jsonplaceholder.typicode.com (GET-only, needs network)
make help    # all targets
```

## Layout

- `cmd/wireaudit` — entry point
- `internal/cli` — flags, run loop
- `internal/probe` — HTTP and raw-socket probes, `Session` (bounded by `probe.MaxRequestsPerRule`)
- `internal/rules` — one file per category; each rule implements `Rule` and calls `Register` from `init()`
- `internal/analyzer`, `internal/report` — orchestration and rendering (human/JSON)

## Adding or changing a rule

- Implement `rules.Rule` in the matching category file; register it in that file's `init()`. Never edit dispatch code.
- IDs are stable: `<CATEGORY>-NNN`. Never renumber or reuse an ID.
- Severity follows the README bucket definitions: Must Fix = MUST-level violation, Should Fix = SHOULD-level, Consider = no normative violation.
- Cite the **current** RFC and section (RFC 9110/9111/9112, not 2616/7230-7235). See the README "Superseded" table.
- Rules that send mutating requests must stay opt-in behind `--allow-unsafe-writes`.

## Keep the README tables in sync (mandatory)

`README.md` has tables that describe what `wireaudit` validates. Any change that alters validated behavior must update them **in the same PR**:

| Change | Update |
|---|---|
| Add, remove, or re-scope a rule; change a cited RFC/section | **Rule catalog (v1)** row (ID, category, RFC/Spec, Verifies) |
| Same | **Coverage → By RFC**: status (Validated / Partial / Not validated), Check IDs, and the "validated / not checked" text |
| Rule closes or opens a REST best-practice gap | **Coverage → By REST best practice**: status and Check IDs |
| Add a flag or change a default | **Configuration** table and **Usage** |
| Cite a new RFC | **References**: add it with its title, role, and current status; move obsolete ones to **Superseded** |
| A planned item ships (HTTP/2, WebSocket, etc.) | Remove it from the "Not yet covered" line and flip its Coverage rows |

Rules for editing the tables:

- Status words are exactly: `Validated`, `Partial`, `Not validated`, `Out of scope`. "Partial" rows must say what is **not** checked.
- Every Check ID in a Coverage row must exist in code; every rule in code must appear in the catalog and at least one Coverage row. Verify with `rg -o '"[A-Z]+-[0-9]{3}"' internal/rules` against the README before finishing.
- Verify RFC status against `https://www.rfc-editor.org/rfc/rfcNNNN.json` (`status`, `obsoleted_by`) rather than from memory.
- Do not claim coverage the code does not implement; read the rule before marking it Validated.
- The REST best-practice table is derived from https://restfulapi.net/. That site is non-normative; RFCs win on conflict.

## Conventions

- Conventional Commits, one `type(scope)` per PR; branch off `main`, never commit to it.
- Every `gh pr create` uses `--assignee "@me"`.
