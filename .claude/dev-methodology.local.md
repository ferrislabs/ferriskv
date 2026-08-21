# dev-methodology preferences (user answers — change only when the user does)
commit: claude-allowed
create-pr: claude-allowed
merge-pr: human-only          # PRs stay open for review; stacked PRs target the previous branch
feature-merge: squash
workstream-merge: squash
tracking: existing GitHub issues (one issue = one PR)
reviewers: none               # never request review automatically
assignee: NathaelB
labels: area:core, area:raft, area:storage, area:auth, area:txn, area:observability, area:deploy, area:proto, area:client, area:sql, type:tracking, type:tech-debt, priority:critical, priority:high, priority:medium, bug, documentation, enhancement, duplicate, good first issue, help wanted, invalid, question, wontfix
model-strategy: current-everywhere
