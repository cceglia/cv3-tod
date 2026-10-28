## Response style

Be concise. No walls of text. Prefer short paragraphs and a few bullets; use a table only when it
carries real structure. No preamble, no restating the question, no summarising work that the diff or
the files already show. If a reply needs more than roughly a screen, cut it or ask.

## CodeGraph

This repo is indexed (`.codegraph/`). Reach for it before grep or reading files when you need to
understand or locate code: the MCP `codegraph_explore` tool (pass this project's path) or
`codegraph explore "<symbols or question>"`. Re-run `codegraph init` after large refactors.

## Agent skills

### Issue tracker

Issues and specs are markdown files under `docs/specs/<id>-<feature-slug>/` in this repo. See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical roles map 1:1 to their own names (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
