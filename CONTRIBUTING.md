# Contributing

Thanks for helping. This guide applies to every Vagary Labs repository that does not ship its own `CONTRIBUTING.md`.

## Before you start

- **Security problems:** do not open an issue. Follow [SECURITY.md](SECURITY.md).
- **Bugs and requests:** open an issue with what happened, what you expected and how to reproduce it. New issues are assigned to the maintainers automatically.
- **Larger changes:** open an issue first so the approach can be agreed before you write code.

## Pull requests

- Keep each pull request to one change.
- Write commit messages in [Conventional Commits](https://www.conventionalcommits.org/) form, for example `fix: handle an empty CSV`.
- Never commit credentials, tokens or `.env` files. Every pull request runs a secret scan (gitleaks and trufflehog), and a finding fails the check.
- Make sure the repository's CI passes.

## Conduct

Contributors follow the [code of conduct](CODE_OF_CONDUCT.md).
