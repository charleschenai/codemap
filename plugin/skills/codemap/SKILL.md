---
name: codemap
description: Analyze codebase dependency structure — trace imports, blast radius, phone-home detection, dead files, circular deps, function callers. Use when asked to understand code structure, audit dependencies, or prepare for refactoring.
user-invocable: true
allowed-tools:
  - Bash(bun *)
  - Bash(graph *)
  - Bash(~/bin/codemap *)
  - Read
  - Grep
---

# /codemap — Codebase Dependency Analysis

Scan a codebase and answer structural questions about it. Run the graph CLI via Bash.

## Usage

The graph tool is at `~/bin/codemap`. Run it with Bun:

```bash
bun ~/bin/codemap [--dir <path>] <action> [target]
```

Default directory is the current working directory.

## Actions

| Action | What | Example |
|--------|------|---------|
| `stats` | Codebase overview (files, lines, imports, URLs) | `graph stats` |
| `trace <file>` | Show imports and importers of a file | `graph trace src/utils/auth.ts` |
| `blast-radius <file>` | All files affected if this changes | `graph blast-radius src/api/client.ts` |
| `phone-home` | Find all files with external URLs | `graph phone-home` |
| `coupling <pattern>` | Find files importing a package/pattern | `graph coupling @anthropic-ai/sdk` |
| `dead-files` | Files nothing imports | `graph dead-files` |
| `circular` | Detect circular dependency chains | `graph circular` |
| `functions <file>` | List exports in a file | `graph functions src/utils/auth.ts` |
| `callers <name>` | Find where a function is used | `graph callers getApiKey` |

## When to Use

- Before deleting or refactoring files — check blast radius first
- When auditing a codebase for security — phone-home finds every external URL
- When understanding a new codebase — stats + trace gives you the architecture
- When cleaning up — dead-files shows what can be removed safely
- When removing a dependency — coupling shows every file that imports it

## Process

1. Run `stats` first to understand the codebase size
2. Use the appropriate action based on what you need to know
3. The scan takes <500ms for most codebases — run it freely
4. Results are plain text, parse them to answer the user's question

## For a Different Directory

```bash
bun ~/bin/codemap --dir ~/Desktop/other-project stats
```
