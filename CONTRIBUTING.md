# Contributing

Commits to this project must adhere to the [Conventional Commits
specification](https://www.conventionalcommits.org/en/v1.0.0/) that will allow
us to automate version bumps and changelog entry creation.

After cloning this repository, you must install the pre-commit hook for
conventional commits:

```sh
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install pre-commit
pre-commit install --install-hooks -t pre-commit -t pre-push -t commit-msg
```
