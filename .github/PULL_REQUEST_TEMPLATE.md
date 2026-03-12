## Description

<!-- Provide a clear summary of the change and the motivation behind it -->

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing behaviour)
- [ ] Refactoring (no functional changes)
- [ ] Performance improvement
- [ ] Documentation update
- [ ] CI/CD / tooling change

## Related Issues

<!-- Link any related issues: "Closes #123", "Fixes #456" -->

## Testing

- [ ] All existing unit tests pass (`cargo test --lib --all`)
- [ ] All integration tests pass (`cargo test --test '*' --all`)
- [ ] New tests added for new behaviour (100% coverage on new code)
- [ ] Tested locally on the target platform(s)

## Security Review

- [ ] No new `unsafe` code introduced (or justified and reviewed)
- [ ] Cryptographic changes reviewed against the security checklist
- [ ] No secrets, API keys, or credentials committed
- [ ] User-supplied input is properly sanitised

## Performance

- [ ] No performance regressions for core operations
- [ ] Performance tested with 1000+ credentials if applicable

## Cross-Platform Compatibility

- [ ] Tested / expected to work on Linux
- [ ] Tested / expected to work on macOS
- [ ] Tested / expected to work on Windows

## Quality Gate Checklist

> All items below must be checked before requesting review.

- [ ] `cargo fmt --all` passes (no formatting issues)
- [ ] `cargo clippy --all-targets --all-features -- -W clippy::all -D warnings` passes
- [ ] `cargo build --all-targets` succeeds
- [ ] `cargo test --all` passes
- [ ] `cargo audit` shows no new vulnerabilities

## Additional Notes

<!-- Any context, screenshots, or extra information reviewers should know -->
