# Contributing

Issues and pull requests are welcome.

- Run the tests before sending a change: `python -m unittest discover -s tests -t tests`.
  Install tmux to run the integration tests too.
- **Changes that touch pairing, tokens, the guard or the write rules** need a test that
  shows the attack they prevent, and a line in `docs/threat-model.md` if the model changes.
- **Never commit real hostnames, tailnet names, account IDs, tokens or secrets**, not even
  in tests or docs. Use `example.com`, `example.test` and `your-machine.your-tailnet.ts.net`.
- Report security issues privately; see [SECURITY.md](SECURITY.md).
