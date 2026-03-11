# Contributing to opencode-log-sanitizer

First off — thanks for taking the time to contribute! 🎉

This is an open-source project and all kinds of contributions are welcome: bug reports, new redaction patterns, docs improvements, tests, ideas.

---

## Ways to contribute

- 🐛 **Report a bug** — open an issue with a clear reproduction case
- 💡 **Suggest a feature** — open an issue describing what you'd like and why
- 🔧 **Fix a bug** — pick an issue, open a PR
- ✨ **Add a new redaction pattern** — e.g. AWS access keys, Stripe secrets, SSH private keys
- 📝 **Improve docs** — clearer examples, better troubleshooting, translations
- 🧪 **Add tests** — edge cases, new input formats

---

## Development setup

You'll need [Bun](https://bun.sh) installed.

```bash
git clone https://github.com/errhythm/opencode-log-sanitizer.git
cd opencode-log-sanitizer
bun install
```

### Useful commands

```bash
bun test            # run the full test suite (32 tests)
bun test --watch    # run tests in watch mode
bun run build       # build dist/
bun run lint        # lint with ESLint
bun run lint:fix    # auto-fix lint issues
```

---

## Adding a new redaction pattern

All redaction logic lives in [`src/sanitizer.ts`](./src/sanitizer.ts). To add a new pattern:

1. Add a new `redactXxx(text)` function following the existing style
2. Add it as a step in the `sanitize()` pipeline
3. Expose any config flag via `SanitizerConfig` with a sensible default
4. Add test cases in [`src/sanitizer.test.ts`](./src/sanitizer.test.ts) covering:
   - A positive match (it gets redacted)
   - A negative match (similar-looking text is left alone)
   - Edge cases

**Important:** regex patterns must not use `.*` or `.+` on long strings — prefer character classes with specific quantifiers to avoid catastrophic backtracking. See the existing patterns for reference.

---

## Submitting a Pull Request

1. Fork the repo and create a branch:
   ```bash
   git checkout -b feat/aws-key-redaction
   ```
2. Make your changes
3. Make sure tests pass and lint is clean:
   ```bash
   bun test && bun run lint
   ```
4. Commit using [Conventional Commits](https://www.conventionalcommits.org/) — PR titles are enforced by CI:
   - `feat: add AWS access key redaction`
   - `fix: handle unterminated strings with escaped backslash`
   - `docs: clarify no-redact bypass syntax`
   - `test: add edge cases for base64 detection`
5. Open a PR with a clear description of what you changed and why

---

## Code style

- TypeScript strict mode
- Single quotes, 2-space indent, 100 char line width (Prettier enforced)
- No `any` types (use specific types or generics)
- No `console.log` (use `client.app.log()` in plugin hooks)
- Early returns over deep nesting (NeverNesters principle)

Run `bun run lint:fix` to auto-fix most style issues.

See [AGENTS.md](./AGENTS.md) for the full code style reference.

---

## Reporting bugs

Open an issue and include:

- What you pasted / typed into OpenCode
- What you expected to happen
- What actually happened
- Your OpenCode version (`opencode --version`)
- Your Bun version (`bun --version`)

If the input contains sensitive data, sanitize it before sharing — you can show just the _shape_ of the input (e.g. `"token": "eyJ....<50 chars>...."`).

---

## Questions?

Open a [GitHub Discussion](https://github.com/errhythm/opencode-log-sanitizer/discussions) or an issue — happy to help.
