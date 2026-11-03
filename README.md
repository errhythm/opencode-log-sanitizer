# opencode-log-sanitizer

> OpenCode plugin that automatically redacts JWT tokens, bcrypt hashes, base64 blobs, long quoted strings, common secret tokens (API keys, GitHub/GitLab tokens, AWS keys, etc.), and passwords from your prompts **before they reach the AI** — reducing token usage and removing irrelevant noise.

[![npm](https://img.shields.io/npm/v/opencode-log-sanitizer)](https://www.npmjs.com/package/opencode-log-sanitizer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

I built this for my own use — I got tired of JWTs and base64 blobs eating up my token budget every time I pasted a log. Figured it might be useful for you too.

---

## Installation

### OpenCode 1.x

Add to your `opencode.jsonc`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-log-sanitizer"]
}
```

With options:

```jsonc
{
  "plugin": [
    ["opencode-log-sanitizer", {
      "maxStringLength": 300,
      "enableJwtDetection": true,
      "enablePasswordDetection": true
    }]
  ]
}
```

### OpenCode 2.x

Requires OpenCode 2.0.5+. Add to your `opencode.json` — note the **plural `plugins` key** and the object form:

```jsonc
{
  "plugins": [
    {
      "package": "opencode-log-sanitizer",
      "options": {
        "maxStringLength": 300,
        "enableJwtDetection": true,
        "enablePasswordDetection": true
      }
    }
  ]
}
```

OpenCode installs npm plugins automatically using Bun at startup. Packages are cached in `~/.cache/opencode/node_modules/`.

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
| Secret tokens (API keys, etc.) | `sk-...`, `ghp_...`, `AKIA...` | `[redacted:secret]`          |
| Passwords                  | `password=secret`, `postgres://user:pass@host` | `[redacted:password]` |

No config needed. Works on any text you type or paste.

---

## Configuration

All options are optional. Defaults work well out of the box.

```jsonc
{
  "plugin": [
    [
      "opencode-log-sanitizer",
      {
        "maxStringLength": 300,
        "enableJwtDetection": true,
        "enableBcryptDetection": true,
        "enableBase64Detection": true,
        "enableSecretDetection": true,
        "enablePasswordDetection": true,
        "debug": false,
        "debugLogFile": "~/.local/share/opencode/opencode-log-sanitizer.debug.log"
      }
    ]
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
| `enablePasswordDetection`| `true`    | Redact passwords in key/value pairs and connection strings |
| `debug`                  | `false`   | Write debug logs to `debugLogFile`            |
| `debugLogFile`           | see below | Path for JSONL debug logs                     |

---

## The `<no-redact>` bypass

Need to include a specific value verbatim? Wrap it in `<no-redact>` tags:

```
I need you to decode this token exactly:
<no-redact>
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
</no-redact>

The rest of my log can be sanitized normally: ...
```

Anything inside `<no-redact>…</no-redact>` is **never touched**, regardless of length or content.

---

## How it works

The plugin ships one package that supports both OpenCode generations.

- **OpenCode 1.x**: the plugin is a function that returns a `chat.message` hook. It sanitizes `parts[].text` of each user message before it is forwarded to the model.
- **OpenCode 2.x**: the plugin default-exports a definition with an `id` and `setup(ctx)`. `setup` registers a `session` prompt hook and a `tool` execute-after hook, sanitizing prompts before admission and tool (shell/bash) output before it reaches the model.

Both implementations share the same sanitizer pipeline and configuration; the host generation is selected automatically from the default export.

Troubleshooting:

- **A value is being redacted that I need**: wrap it in `<no-redact>…</no-redact>` tags, or disable the relevant detector via config.
- **Nothing seems to be happening (v1)**: make sure the plugin is listed under `"plugin"` in `opencode.jsonc`, then restart OpenCode.
- **Nothing seems to be happening (v2)**: make sure the plugin is listed under `"plugins"` in `opencode.json` using the object form, then restart OpenCode. Check the debug log at `~/.local/share/opencode/opencode-log-sanitizer.debug.log` (enable `debug: true`).
- **JWT detection** requires the three-part `header.payload.signature` format starting with `eyJ`, with each segment ≥ 10 characters.
- **Base64 detection** requires at least one `+` or `/` character in the blob. Pure alphanumeric strings (e.g. hex hashes, UUIDs) are intentionally not matched to avoid false positives.
- **Password detection** matches `password`/`passwd`/`pwd` followed by `=` or `:` and a value, plus credentials in `://user:pass@host` connection strings.

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
bun test          # test cases
bun run build     # build dist/
bun run lint      # lint
```

---

## License

[MIT](LICENSE) © [Ehsanur Rahman Rhythm](https://github.com/errhythm)
