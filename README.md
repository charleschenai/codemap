# graph

Codebase dependency analysis. Zero dependencies. Single file.

## Install

```bash
# Requires Bun (https://bun.sh)
bun link
```

## Usage

```bash
graph trace src/utils/auth.ts        # who imports this, what it imports
graph blast-radius src/api/client.ts  # everything affected if this changes
graph phone-home                      # find all external URLs
graph coupling @some/package          # find files importing a package
graph dead-files                      # files nothing imports
graph circular                        # detect circular dependencies
graph functions src/utils/auth.ts     # list exports in a file
graph callers getApiKey               # find where a function is used
graph stats                           # codebase overview

# Scan a different directory
graph --dir ~/Desktop/my-project stats
```

## How it works

Regex-based import scanning. No AST, no tree-sitter, no dependencies. Scans any language that uses import/require/from statements. Builds the full import graph in memory, answers structural queries instantly.

## Supported Languages

TypeScript, JavaScript, Python, Rust, Go, Java, Ruby, PHP — anything with string-based imports.
