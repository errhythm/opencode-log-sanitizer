# opencode-log-sanitizer-v2

> OpenCode plugin that automatically redacts JWT tokens, bcrypt hashes, base64 blobs, long quoted strings, and common secret tokens (API keys, GitHub/GitLab tokens, AWS keys, etc.) from your prompts **before they reach the AI** — reducing token usage and removing irrelevant noise.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

I built this for my own use — I got tired of JWTs and base64 blobs eating up my token budget every time I pasted a log. Figured it might be useful for you too.

---

## Installation

### opencode 1.x

Add to your `opencode.jsonc`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-log-sanitizer-v2"]
}
```

With options:

```jsonc
{
  "plugin": [
    ["opencode-log-sanitizer-v2", {
      "maxStringLength": 300,
      "enableJwtDetection": true,
      "debug": false
    }]
  ]
}
```

### opencode 2.x

Requires opencode 2.0.5+. Add to your `opencode.json` — note the **plural `plugins` key** and the object form; options under v1's singular `plugin` key load but are never delivered on v2:

```jsonc
{
  "plugins": [
    {
      "package": "opencode-log-sanitizer-v2",
      "options": {
        "maxStringLength": 300,
        "enableJwtDetection": true,
        "debug": false
      }
    }
  ]
}
```

Local development (this repo):

```jsonc
{
  "plugin": [
    "file:///home/famewolf/projects/opencode/opencode-log-sanitizer-v2"
  ]
}
```

To uninstall, delete the entry from `opencode.jsonc` (v1: the `plugin` array item, v2: the `plugins` object) and restart the server. To clear the cached copy too, remove `~/.cache/opencode/packages/opencode-log-sanitizer-v2@*`.

Restart OpenCode. Done. Sensitive values in your prompts are redacted automatically before they reach the model.

---

## What it does

When you paste a large log into OpenCode, the plugin sanitizes it before the AI sees it:

| Pattern                    | Example                         | Replacement                  |
| -------------------------- | ------------------------------- | ---------------------------- |
| JWT tokens                 | `eyJhbGci...header.payload.sig` | `[redacted:jwt]`             |
| bcrypt hashes              | `$2b$10$abc...`                 | `[redacted:bcrypt]`          |
| base64 blobs ≥ 300 chars   | `iVBORw0KGgo....(900 chars)`    | `[redacted:base64:984chars]` |
| Quoted strings ≥ 300 chars | `"a very long token value..."`  | `"redacted"`                 |
| API keys / access tokens   | `sk-...`, `ghp_...`, `AKIA...`  | `[redacted:secret]`          |

No config needed. Works on any text you type or paste.

---

## Configuration

All options are optional. Pass them via your plugin config:

```jsonc
{
  "plugin": [
    "file:///home/famewolf/projects/opencode/opencode-log-sanitizer-v2",
    {
      "maxStringLength": 300,
      "enableJwtDetection": true,
      "enableBcryptDetection": true,
      "enableBase64Detection": true,
      "enableSecretDetection": true,
      "debug": false,
      "debugLogFile": "~/.local/share/opencode/opencode-log-sanitizer.debug.log"
    }
  ]
}
```

| Option                   | Default   | Description                                  |
| ------------------------ | --------- | -------------------------------------------- |
| `maxStringLength`        | `300`     | Max chars before quoted strings/base64 are redacted |
| `enableJwtDetection`     | `true`    | Redact JWT tokens (`eyJ...`)                  |
| `enableBcryptDetection`  | `true`    | Redact bcrypt hashes (`$2b$...`)              |
| `enableBase64Detection`  | `true`    | Redact base64 blobs (≥ maxStringLength chars) |
| `enableSecretDetection`  | `true`    | Redact secret tokens (API keys, etc.)         |
| `debug`                  | `false`   | Write debug logs to `debugLogFile`            |
| `debugLogFile`           | see below | Path for JSONL debug logs                     |

---

## What it does not redact

- Plain alphanumeric strings shorter than `maxStringLength` (e.g. hex hashes, UUIDs) — intentional, to avoid false positives
- Anything inside `<no-redact>…</no-redact>` tags

---

## How it works

The plugin hooks into OpenCode's v2 plugin API:

- **`session.execution.started`** — detects when a new execution begins (gated to avoid wiping the counter on your own stall-continue injects)
- **`session.tool.failed` / `session.step.started`** — tracks tool failures and step progress
- **`session.prompt`** — sanitizes user prompts before they reach the model
- **`execute.after` (shell/bash)** — sanitizes tool output before it reaches the model

Counters are gated so that your own stall-continue injects do not reset the visible progress counter, and the rung claim is released if a nudge is never consumed (suppressed/declined), so the ordinal never advances on a nudge that never lands.

---

## Troubleshooting

**Something isn't being redacted**

- Check `maxStringLength` — if the value is a bare (unquoted) string shorter than 300 chars, it won't be caught by the quoted-string rule. Wrap it manually or lower the threshold.
- JWT detection requires the three-part `header.payload.signature` format starting with `eyJ`, with each segment ≥ 10 characters.
- Base64 detection requires at least one `+` or `/` character in the blob. Pure alphanumeric strings (e.g. hex hashes, UUIDs) are intentionally not matched to avoid false positives.

**A value is being redacted that I need**

- Wrap it in `<no-redact>…</no-redact>` tags.

**Nothing seems to be happening**

- Make sure the plugin is listed in `opencode.jsonc` under `"plugin"`.
- Restart OpenCode after config changes.
- Check the debug log at `~/.local/share/opencode/opencode-log-sanitizer.debug.log` (enable `debug: true`).

---

## Contributing

Contributions are welcome!

- Found a bug? [Open an issue](https://github.com/errhythm/opencode-log-sanitizer/issues)
- Have an idea? [Start a discussion](https://github.com/errhythm/opencode-log-sanitizer/discussions)
- Want to add a new redaction pattern? See [CONTRIBUTING.md](./CONTRIBUTING.md)

---

## Development

```bash
git clone https://github.com/errhythm/opencode-log-sanitizer.git
cd opencode-log-sanitizer
bun install
bun test          # 38 test cases
bun run build     # build dist/
bun run lint      # lint
```

---

## License

[MIT](LICENSE) © [Ehsanur Rahman Rhythm](https://github.com/errhythm)