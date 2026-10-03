# AGENTS.md — RoamSentinel (`RoamSentinel`)

Project commands:
- Setup: _fill in_
- Test:  `dotnet test .\RoamSentinel.slnx`
- Lint:  _fill in_
- Build: `dotnet build .\RoamSentinel.slnx`

## Devhub workflow (multi-agent rules, added 2026-10-03)
This repo is managed from `C:\dev`. Hub rules: `C:\dev\AGENTS.md`.
- Source of truth: `C:\dev\apps\RoamSentinel`. Never edit it directly. Claim a scoped task
  (`devhub claim RoamSentinel "<task>" --agent <you> --scope <paths>`) and work in the worktree
  you get under `C:\dev\wt\RoamSentinel\`.
- Read the latest handoffs in `C:\dev\ledger\handoffs\RoamSentinel\` first and build on them.
- Log decisions/blockers with `devhub log`. Finish with `devhub done` and then `devhub integrate`.
- Never commit secrets. They live in `C:\dev\secrets\RoamSentinel\`.
- Cloud sessions (claude.ai/code) start from `main`, work on a branch named `agent/cloud/<task>`, push only that branch and never push to `main`. The owner brings it in on the PC with `devhub adopt RoamSentinel agent/cloud/<task>`, then `devhub done` and `devhub integrate`. Don't open a pull request; integration goes through devhub.
