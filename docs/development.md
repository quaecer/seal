# Development

Start with `uv sync --locked`. Run `uv run --locked pytest` and
`uv run --locked mypy src` from the directory containing `pyproject.toml`.
Install the hooks with `uv run --locked pre-commit install` from the repository
root with the locked development environment active.
The secret-scanning hook needs Gitleaks on `PATH`.

Use a single-line Conventional Commit subject for commits and pull request
titles, such as `feat: add export` or `fix(parser): validate dates`.
Squash with the pull request title followed by the pull request number in
parentheses and leave the commit body empty.
Run `python3 .github/gate.py` with the maintainer's pattern environment before promotion.

Set `GATE_GITHUB_REPOSITORY` to the GitHub owner and repository and authenticate
`gh` to include all pull request and issue text in the publication scan.
CI scans repository text for owner branches. Run a maintainer scan before
promotion. Repository settings remove merged topic branches.
