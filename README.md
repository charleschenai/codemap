# codemap

Codebase dependency analysis. Zero dependencies. Single file.

## Install

```bash
# Requires Bun (https://bun.sh)
bun link
```

## Usage

```bash
codemap trace src/utils/auth.ts        # who imports this, what it imports
codemap blast-radius src/api/client.ts  # everything affected if this changes
codemap phone-home                      # find all external URLs
codemap coupling @some/package          # find files importing a package
codemap dead-files                      # files nothing imports
codemap circular                        # detect circular dependencies
codemap functions src/utils/auth.ts     # list exports in a file
codemap callers getApiKey               # find where a function is used
codemap stats                           # codebase overview

# Scan a different directory
codemap --dir ~/Desktop/my-project stats
```

## How it works

Regex-based import scanning. No AST, no tree-sitter, no dependencies. Scans any language that uses import/require/from statements. Builds the full import graph in memory, answers structural queries instantly.

## Supported Languages

TypeScript, JavaScript, Python, Rust, Go, Java, Ruby, PHP — anything with string-based imports.
