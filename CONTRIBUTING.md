# Contributing to PassManager

Contributions are welcome: bug reports, security reviews, documentation, and code.

PassManager is licensed under the [PolyForm Strict License 1.0.0](LICENSE) with the [PassManager Contribution Terms](LICENSE-CONTRIBUTING.md). You may fork this repository and change the code **only to prepare contributions** to it. Forks may not be distributed, published as builds, or maintained as separate versions. By opening a pull request you agree to the Contribution Terms.

## Workflow

1. Fork the repository on GitHub and create a branch.
2. Make your change. Keep it focused and match the surrounding code style.
3. Run the checks:

   ```sh
   cargo fmt --all
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace --features pm-crypto/test-hooks
   ```

   See the "Development" section of [README.md](README.md) for build prerequisites (CMake, a C compiler, libclang).
4. Open a pull request against `main` and describe what changed and why. CI runs on Linux, macOS, and Windows (x64 and arm64).

## Security issues

Do not open a public issue for a vulnerability. Report it privately through GitHub's "Report a vulnerability" (Security tab) of this repository.
