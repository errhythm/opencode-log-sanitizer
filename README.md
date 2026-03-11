# opencode-log-sanitizer

[![npm version](https://img.shields.io/npm/v/opencode-log-sanitizer)](https://www.npmjs.com/package/opencode-log-sanitizer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> An [OpenCode](https://opencode.ai) plugin that automatically redacts sensitive and noisy values from your prompts before they are sent to the AI model.

Pasting large logs into an AI prompt is common during debugging — but logs often contain JWT tokens, bcrypt hashes, base64-encoded blobs, and arbitrarily long strings that are useless to the model and waste tokens. This plugin sanitizes the prompt transparently, without you having to think about it.

---

## What gets redacted?

| Pattern | Example | Replacement |
|---|---|---|
| JWT tokens | `eyJhbGci...` | `redacted` |
| bcrypt hashes | `$2b$10$abc...` | `redacted` |
| base64 blobs ≥ 300 chars | `AAAAAAA...` | `redacted` |
| Quoted strings ≥ 300 chars | `"very long value..."` | `"redacted"` |

---

## Installation

### From npm (in your OpenCode config directory)

Add a `package.json` to your OpenCode config directory (`~/.config/opencode/` on macOS/Linux):

```json
{
  "dependencies": {
    "opencode-log-sanitizer": "latest"
  }
}
```

OpenCode will run `bun install` automatically at startup.

### From a local file

Copy this project to your OpenCode config directory and reference it as a local plugin (see below).

---

## Setup

Add the plugin to your `opencode.json`:

```json
{
  "plugins": {
    "opencode-log-sanitizer": {}
  }
}
```

With custom configuration:

```json
{
  "plugins": {
    "opencode-log-sanitizer": {
      "maxStringLength": 200,
      "enableJwtDetection": true,
      "enableBcryptDetection": true,
      "enableBase64Detection": true
    }
  }
}
```

---

## Configuration

| Option | Type | Default | Description |
|---|---|---|---|
| `maxStringLength` | `number` | `300` | Quoted strings or base64 blobs longer than this are redacted |
| `enableJwtDetection` | `boolean` | `true` | Detect and redact JWT tokens (`eyJ...`) |
| `enableBcryptDetection` | `boolean` | `true` | Detect and redact bcrypt hashes (`$2a$`, `$2b$`, `$2y$`) |
| `enableBase64Detection` | `boolean` | `true` | Detect and redact base64 blobs longer than `maxStringLength` |

---

## Usage Examples

### JWT token in an authorization header

**Input:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
```

**Output:**
```
Authorization: Bearer redacted
```

---

### bcrypt hash in a JSON log

**Input:**
```json
{"email": "user@example.com", "passwordHash": "$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"}
```

**Output:**
```json
{"email": "user@example.com", "passwordHash": "redacted"}
```

---

### Long base64 blob

**Input:**
```
thumbnail: iVBORw0KGgoAAAANSUhEUgAA....(900 more chars)....
```

**Output:**
```
thumbnail: redacted
```

---

## The `<no-redact>` bypass

If you need to include a specific value in the prompt without it being redacted, wrap it in `<no-redact>` blocks:

```
Here is the exact token I need you to analyse:
<no-redact>
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
</no-redact>
The rest of this log can be sanitized normally: ...
```

Anything inside `<no-redact>…</no-redact>` is **never modified**, regardless of configuration.

---

## How it works

The plugin hooks into OpenCode's `tui.prompt.append` event, which fires just before your message is sent to the AI. The sanitization pipeline runs in this order:

1. **Extract** `<no-redact>` blocks → replace with temporary placeholders
2. **Redact** JWT tokens
3. **Redact** bcrypt hashes
4. **Redact** long base64 blobs
5. **Redact** long quoted strings (using a safe, linear-time scanner — no catastrophic regex backtracking)
6. **Restore** `<no-redact>` placeholder blocks

The plugin logs redaction statistics (count, saved characters) via OpenCode's structured logging API.

---

## Development

```bash
bun install         # Install dependencies
bun test            # Run tests
mise run build      # Build the module
mise run lint       # Lint code
mise run format     # Format with Prettier
```

---

## License

[MIT](LICENSE) © Ehsanur Rahman Rhythm
