## What and why

<!-- What this changes and the problem it solves. Link the issue it fixes. -->

## Checks

<!-- The commands you ran and their results. Say which checks you did not run. -->

- [ ] `scripts/check-privacy.sh` and `python3 -I scripts/check-module-size.py`
- [ ] `cargo fmt --all -- --check`, `cargo clippy --release --locked --all-targets -- -D warnings`, `cargo test --release --locked`
- [ ] Build-script, shell or VM checks for the parts this touches
- [ ] Documentation updated for user-visible changes

By opening this pull request I confirm I may contribute this change under the
destination file's license (see LICENSING.md).
