# Proxy project

## Build

```bash
cargo build --release
cargo fmt -- --check && cargo clippy -- -D warnings   # required before commit
```

### On a workstation with `rbuild`, compile remotely

If `rbuild` is on `PATH`, prefer it: it rsyncs the working tree — uncommitted
changes included — to the dedicated build server, runs cargo there on twelve
cores, and pulls only the executables back. Everywhere else (CI runners, a fresh
clone, another machine) `rbuild` is absent and the commands above are the right
ones.

```bash
rbuild proxy         # replaces cargo build --release
rbuild check proxy   # replaces the fmt + clippy gate, in about twenty seconds
```

`soli-proxy`, `httptest` and `hash-password` land in `target/remote/release/`
and are linked into `Work/soli/bin/`, first on `PATH`. The local `target/` was
deleted when compilation moved off this machine, so a local `cargo build` now
starts from nothing.

Note the remote release binary is not the manifest's: the server overrides `lto`
to `thin` and `codegen-units` to 16, and a `[profile.*]` table in a cargo config
outranks `Cargo.toml` key by key. Benchmark with `rbuild --faithful proxy`.

`sites/` and `run/` are not synced — they are runtime state, not build input.

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
