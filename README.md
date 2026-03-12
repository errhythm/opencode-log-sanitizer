# opencode-log-sanitizer

> OpenCode plugin that automatically redacts JWT tokens, bcrypt hashes, base64 blobs, and long quoted strings from your prompts **before they reach the AI** — reducing token usage and removing irrelevant noise.

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

No config needed. Works on any text you type or paste.

---

## How it works

The plugin hooks into OpenCode's **`chat.message`** event. This hook fires just before the user message is forwarded to the LLM, and provides a mutable `output.parts` array. The plugin iterates over every `TextPart` and runs the sanitization pipeline on its `.text` field.

> **Why not `tui.prompt.append`?**  
> `tui.prompt.append` fires when text is appended to the TUI input box. It is a notification event — mutating its output does **not** change what gets sent to the model. `chat.message` is the correct interception point.

The sanitization pipeline runs in this order:

1. Extract `<no-redact>` blocks → replace with temporary placeholders
2. Redact JWT tokens → `[redacted:jwt]`
3. Redact bcrypt hashes → `[redacted:bcrypt]`
4. Redact base64 blobs longer than `maxStringLength` → `[redacted:base64:Nchars]`
5. Redact quoted strings longer than `maxStringLength` → `"redacted"` (linear-time scanner, no regex backtracking)
6. Restore the `<no-redact>` placeholders

---

## Installation

### From npm (recommended)

Add the plugin to your `opencode.json`:

```json
{
  "plugin": ["opencode-log-sanitizer"]
}
```

OpenCode installs npm plugins automatically using Bun at startup. Packages are cached in `~/.cache/opencode/node_modules/`.

### From a local file

Copy `dist/index.js` into `.opencode/plugins/` in your project (or `~/.config/opencode/plugins/` globally). OpenCode loads all files in those directories at startup.

---

## Configuration

All options are optional. Defaults work well out of the box.

```json
{
  "plugin": [
    [
      "opencode-log-sanitizer",
      {
        "maxStringLength": 300,
        "enableJwtDetection": true,
        "enableBcryptDetection": true,
        "enableBase64Detection": true
      }
    ]
  ]
}
```

| Option                  | Type      | Default | Description                                                  |
| ----------------------- | --------- | ------- | ------------------------------------------------------------ |
| `maxStringLength`       | `number`  | `300`   | Quoted strings or base64 blobs longer than this are redacted |
| `enableJwtDetection`    | `boolean` | `true`  | Redact JWT tokens (`eyJ...header.payload.sig`)               |
| `enableBcryptDetection` | `boolean` | `true`  | Redact bcrypt hashes (`$2a$`, `$2b$`, `$2y$`)                |
| `enableBase64Detection` | `boolean` | `true`  | Redact base64 blobs longer than `maxStringLength` chars      |

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
  "passwordHash": "[redacted:bcrypt]",
  "token": "[redacted:jwt]",
  "avatar": "[redacted:base64:984chars]"
}
```

---

## Troubleshooting

**My value isn't being redacted**

- Check `maxStringLength` — if the value is a bare (unquoted) string shorter than 300 chars, it won't be caught by the quoted-string rule. Wrap it manually or lower the threshold.
- JWT detection requires the three-part `header.payload.signature` format starting with `eyJ`, with each segment ≥ 10 characters.
- Base64 detection requires at least one `+` or `/` character in the blob. Pure alphanumeric strings (e.g. hex hashes, UUIDs) are intentionally not matched to avoid false positives.

**A value is being redacted that I need**

- Wrap it in `<no-redact>…</no-redact>` tags.

**Nothing seems to be happening**

- Make sure the plugin is listed in `opencode.json` under `"plugin"`.
- Restart OpenCode after config changes.

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
