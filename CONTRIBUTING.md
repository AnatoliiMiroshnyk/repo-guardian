# Contributing

Thanks for helping improve Repo Guardian.

1. Open an issue for significant behavior changes.
2. Keep changes focused and explain user impact.
3. Never add real credentials, private repository data, or sample tokens that could be mistaken for valid credentials.
4. Run:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets --all-features -- -D warnings
   cargo test --all-targets
   ```
5. Update README and tests when changing scanner behavior.

Pull requests should describe the problem, approach, validation, and any security/privacy implications.
