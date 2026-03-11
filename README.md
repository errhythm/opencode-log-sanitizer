# opencode-log-sanitizer

> OpenCode plugin that automatically redacts JWT tokens, bcrypt hashes, base64 blobs, and long quoted strings from your prompts before they reach the AI — reducing token usage and removing irrelevant noise.

[![npm](https://img.shields.io/npm/v/opencode-log-sanitizer)](https://www.npmjs.com/package/opencode-log-sanitizer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

I built this for my own use — I got tired of JWTs and base64 blobs eating up my token budget every time I pasted a log. Figured it might be useful for you too.

---

## Quick Start

Add this to your `opencode.json`:

```json
{
  "plugin": ["opencode-log-sanitizer"]
}
```

Restart OpenCode. Done. Sensitive values in your prompts are redacted automatically.

---

## What it does

When you paste a large log into OpenCode, the plugin silently sanitizes it before it reaches the AI:

| Pattern | Example | Replacement |
|---|---|---|
| JWT tokens | `eyJhbGci...` | `redacted` |
| bcrypt hashes | `$2b$10$abc...` | `redacted` |
| base64 blobs ≥ 300 chars | `iVBORw0KGgo....(900 chars)` | `redacted` |
| Quoted strings ≥ 300 chars | `"a very long token value..."` | `"redacted"` |

No config needed. Works on any text you type or paste.

---

## Installation

### From npm (recommended)

Add a `package.json` to your OpenCode config directory (`~/.config/opencode/` on macOS/Linux):

```json
{
  "dependencies": {
    "opencode-log-sanitizer": "latest"
  }
}
```

OpenCode runs `bun install` at startup automatically.

### From a local file

Clone this repo, build it, and reference it as a local plugin path in `opencode.json`.

---

## Configuration

All options are optional. Defaults work well out of the box.

```json
{
  "plugin": [
    ["opencode-log-sanitizer", {
      "maxStringLength": 300,
      "enableJwtDetection": true,
      "enableBcryptDetection": true,
      "enableBase64Detection": true
    }]
  ]
}
```

| Option | Type | Default | Description |
|---|---|---|---|
| `maxStringLength` | `number` | `300` | Quoted strings or base64 blobs longer than this are redacted |
| `enableJwtDetection` | `boolean` | `true` | Redact JWT tokens (`eyJ...header.payload.sig`) |
| `enableBcryptDetection` | `boolean` | `true` | Redact bcrypt hashes (`$2a$`, `$2b$`, `$2y$`) |
| `enableBase64Detection` | `boolean` | `true` | Redact base64 blobs longer than `maxStringLength` chars |

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

## Before / After

**Before (what you type):**

```json
{
  "email": "user@example.com",
  "passwordHash": "$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  "avatar": "iVBORw0KGgoAAAANSUhEUgAAAoAAAAKACAYAAAAMuvCsAAA....(900 more chars)...."
}
```

**After (what the AI sees):**

```json
{
  "email": "user@example.com",
  "passwordHash": "redacted",
  "token": "redacted",
  "avatar": "redacted"
}
```

---

## How it works

The plugin hooks into OpenCode's `tui.prompt.append` event — which fires just before your message is committed to the AI. The sanitization pipeline runs in this order:

1. Extract `<no-redact>` blocks → replace with temporary placeholders
2. Redact JWT tokens
3. Redact bcrypt hashes
4. Redact base64 blobs longer than `maxStringLength`
5. Redact quoted strings longer than `maxStringLength` (using a safe, linear-time scanner — no catastrophic regex backtracking)
6. Restore the `<no-redact>` placeholders

The plugin logs redaction stats (count, saved characters) via OpenCode's structured logging API so you can see what was cleaned up.

---

## Troubleshooting

**My value isn't being redacted**
- Check `maxStringLength` — if the value is a bare (unquoted) string shorter than 300 chars, it won't be caught by the quoted-string rule. Wrap it manually or lower the threshold.
- JWT detection requires the three-part `header.payload.signature` format starting with `eyJ`.

**A value is being redacted that I need**
- Wrap it in `<no-redact>…</no-redact>` tags.

**Nothing seems to be happening**
- Make sure the plugin is listed in `opencode.json` under `"plugin"`.
- Restart OpenCode after config changes.

---

## Contributing

Contributions are welcome!

- 🐛 Found a bug? [Open an issue](https://github.com/errhythm/opencode-log-sanitizer/issues)
- 💡 Have an idea? [Start a discussion](https://github.com/errhythm/opencode-log-sanitizer/discussions)
- 🔧 Want to add a new redaction pattern? See [CONTRIBUTING.md](./CONTRIBUTING.md)

---

## Development

```bash
git clone https://github.com/errhythm/opencode-log-sanitizer.git
cd opencode-log-sanitizer
bun install
bun test          # 32 test cases
bun run build     # build dist/
bun run lint      # lint
```

---

## License

[MIT](LICENSE) © [Ehsanur Rahman Rhythm](https://github.com/errhythm)
