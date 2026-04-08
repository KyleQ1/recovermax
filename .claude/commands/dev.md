---
description: RecoverMax development workflow — build, test, deploy, and manage features
argument-hint: [build|test|release|deploy|feature <name>|welles-test|status]
---

You are working on RecoverMax, a data recovery tool at ~/Workspace/recovermax.

Based on the argument, do the following:

## `build`
Build the project and report any errors:
```
source "$HOME/.cargo/env" && cd ~/Workspace/recovermax && cargo build --workspace 2>&1
```

## `test`
Run all tests and report results:
```
source "$HOME/.cargo/env" && cd ~/Workspace/recovermax && cargo test --workspace 2>&1
```
Count total tests and report pass/fail summary.

## `release`
Build release binaries:
```
source "$HOME/.cargo/env" && cd ~/Workspace/recovermax && cargo build --release --workspace 2>&1
```

## `deploy`
Build the Next.js website and report:
```
cd ~/Workspace/recovermax/website && npm run build 2>&1
```

## `feature <name>`
Implement a new feature. Use an isolated worktree:
1. Read CLAUDE.md for coding standards and project context
2. Launch an Agent with `isolation: "worktree"` to implement the feature
3. The agent should write code AND tests
4. After the agent completes, merge the worktree branch into main
5. Run `cargo test` to verify nothing broke
6. Commit with a clear message

## `welles-test`
Sync code to welles, build, and test against real disk images:
```
rsync -av --exclude target --exclude .git --exclude test-images --exclude node_modules ~/Workspace/recovermax/ welles:/tmp/recovermax-build/
ssh welles 'cd /tmp/recovermax-build && source "$HOME/.cargo/env" && cargo build --release 2>&1 | tail -5'
ssh welles '/tmp/recovermax-build/target/release/recovermax info /projects/reiner-recovery/reiner-sda.img'
```
Report all output. Read-only operations only on disk images.

## `status`
Report project status:
1. Git log (last 5 commits)
2. Test count (`cargo test 2>&1 | grep "test result"`)
3. Any uncommitted changes
4. Current branch

## No argument / unknown
Show available subcommands and a brief description of each.

## General rules
- Always use `source "$HOME/.cargo/env"` before cargo commands
- Never commit without being asked
- Follow KISS coding standards from CLAUDE.md
- Never add AI attribution to commits
- CLAUDE.md is gitignored — never commit it
