## What and why

<!-- What does this change, and why is it needed? Link the issue: Fixes #123 -->

## How it was tested

<!-- Commands you ran, new tests, manual checks. -->

## Checklist

- [ ] Tests cover the new behaviour, including the "refuse" cases.
- [ ] No `unwrap`, `expect`, `panic!` or unchecked indexing in code that runs inside PostgreSQL.
- [ ] No token, or part of one, can reach a log line.
- [ ] `cargo fmt` and `cargo clippy` pass.
- [ ] `CHANGELOG.md` updated under **Unreleased** (if users will notice).
- [ ] Docs updated (README, settings) if behaviour changed.
