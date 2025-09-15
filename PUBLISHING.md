# Publishing Guide for CVE Explorer Pro

This document outlines the steps to publish CVE Explorer Pro to crates.io and manage releases.

## Prerequisites

1. **GitHub Account**: Repository already set up at https://github.com/kayo09/ForMistakeLearning
2. **crates.io Account**: Sign up at https://crates.io using GitHub OAuth
3. **Cargo Token**: Generate API token from crates.io account settings

## Setup GitHub Secrets

For automated releases to work, add these secrets to your GitHub repository:

1. Go to: `https://github.com/kayo09/ForMistakeLearning/settings/secrets/actions`
2. Add secret: `CARGO_REGISTRY_TOKEN` with your crates.io API token

## Manual Publishing Process

### 1. Prepare for Release

```bash
# Ensure you're on the main branch and up to date
git checkout main
git pull origin main

# Run all checks locally
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo doc --no-deps --all-features

# Test dry-run publish
cargo publish --dry-run
```

### 2. Create Release

```bash
# Update version in Cargo.toml if needed
# Update CHANGELOG.md with release notes

# Commit version changes
git add .
git commit -S -m "🏷️ Prepare for v0.1.0 release"
git push origin main

# Create and push tag
git tag -s v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

### 3. Manual Publish (if automated fails)

```bash
# Login to crates.io
cargo login

# Publish to crates.io
cargo publish
```

## Automated Release Process

The repository is configured for automated releases:

### GitHub Actions Workflows

1. **CI Pipeline** (`.github/workflows/ci.yml`):
   - Runs on every push/PR
   - Tests across multiple platforms (Linux, Windows, macOS)
   - Tests with stable and beta Rust
   - Runs clippy, formatting, and security audits
   - Builds documentation
   - Tests examples

2. **Release Pipeline** (`.github/workflows/release.yml`):
   - Triggers on version tags (`v*.*.*`)
   - Creates GitHub release with changelog
   - Builds cross-platform binaries
   - Automatically publishes to crates.io
   - Uploads release assets

### Automated Release Steps

1. **Update version** in `Cargo.toml`
2. **Update CHANGELOG.md** with release notes
3. **Commit and push** changes
4. **Create and push tag**: `git tag v0.1.0 && git push origin v0.1.0`
5. **GitHub Actions** will automatically:
   - Create GitHub release
   - Publish to crates.io
   - Build and upload binaries

## Post-Release

After successful publication:

1. **Verify on crates.io**: https://crates.io/crates/cve_explorer_pro
2. **Check docs.rs**: https://docs.rs/cve_explorer_pro
3. **Update README badges** if needed
4. **Announce release** on social media, forums, etc.

## Version Management

This project uses [Semantic Versioning](https://semver.org/):

- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible functionality additions
- **PATCH**: Backwards-compatible bug fixes

## Release Checklist

- [ ] All tests pass locally
- [ ] Documentation builds without warnings
- [ ] Examples work correctly
- [ ] Version updated in `Cargo.toml`
- [ ] `CHANGELOG.md` updated
- [ ] Changes committed and pushed
- [ ] Tag created and pushed
- [ ] GitHub Actions completed successfully
- [ ] crates.io publication verified
- [ ] docs.rs generation verified

## Troubleshooting

### Common Issues

1. **Publishing fails**: Check `cargo publish --dry-run` first
2. **GitHub Action fails**: Check secrets are properly set
3. **Documentation fails**: Ensure all doc comments are valid
4. **Examples fail**: Test examples locally before release

### Rollback

If a release has issues:

1. **Yank from crates.io**: `cargo yank --vers 0.1.0`
2. **Fix issues and release patch version**
3. **Never delete tags** - use new version instead

## Links

- **Repository**: https://github.com/kayo09/ForMistakeLearning
- **crates.io**: https://crates.io/crates/cve_explorer_pro
- **Documentation**: https://docs.rs/cve_explorer_pro
- **Issues**: https://github.com/kayo09/ForMistakeLearning/issues