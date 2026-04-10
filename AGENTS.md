# Proxy project

## Commit messages

All commit messages MUST follow [Conventional Commits](https://www.conventionalcommits.org/) for semantic release.

- Format: `type(scope): description` (scope optional).
- Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build`.
- Use imperative, lowercase after the colon. Example: `feat(auth): add token validation`.

When suggesting or generating a commit message, always output this format.

## Release workflow

Use `scripts/release.sh` to release a new version. It bumps the version in Cargo.toml, commits, creates a tag, and pushes.

```bash
./scripts/release.sh patch  # 0.22.19 -> 0.22.20
./scripts/release.sh minor  # 0.22.19 -> 0.23.0
./scripts/release.sh major  # 0.22.19 -> 1.0.0
```

Tag format: `v{version}` (e.g., `v0.22.19`).

CI validates that any pushed tag matches the Cargo.toml version before releasing.
