# Build-agent workflow

Project-only authorization: Luna and Terra. Never change global configuration.
The competition runtime does not select these builders as inference providers.

| Role | Model | Effort | Responsibility |
|---|---|---|---|
| named planner | gpt-5.6-luna | xhigh | contracts and bounded implementation plan |
| enforcement worker | gpt-5.6-terra | high | policy, ledger, audit, constrained transport |
| named implementer | gpt-5.6-luna | high | collectors, parsers, skills, bounded interfaces |
| named reviewer | gpt-5.6-luna | high | independent functional and adversarial review |
| main integrator | current main model | current | shared contracts, migration, dependency locks, integration, acceptance |

Each dispatch carries an exact worktree, allowed files, frozen interfaces,
ordered changes, validation commands, acceptance conditions and a stopping
condition. Use compact self-contained context (`fork_turns=none`). Never pass
live target credentials or raw engagement data. No automatic model fallback.

At most two writers may work concurrently on disjoint files. Shared types and
migrations have one owner. Workers must preserve others' changes, communicate
interface conflicts and return exact test evidence. Main checks diffs and runs
integration tests. Reviewers never approve their own changes. Subagents do not
commit or stage shared changes; main owns local commits and release decisions.

Missing model capability blocks only its assignment. Do not substitute another
model silently. Test failures and security findings are fixed before release;
an unavailable live lab remains an explicit acceptance gap.

Build progress is recorded under this plan's local `.superpowers/sdd` workspace.
Do not copy native agent authentication files, private reasoning or client logs.
