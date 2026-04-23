# codemap

Rust-native codebase dependency analysis. 42 actions across 12 languages with cross-language bridge detection.

## Install

```bash
# As a CLI tool
cargo build --release
ln -sf $(pwd)/target/release/codemap ~/bin/codemap

# As a Claude Code plugin
bash install.sh
```

## Usage

```bash
codemap --dir /path/to/src <action> [target]
codemap --dir src stats                    # Codebase overview
codemap --dir src pagerank                 # Most important files
codemap --dir src call-graph function_name # Cross-file call graph
codemap --dir src data-flow file.rs        # Data flow analysis
codemap --dir src lang-bridges             # Cross-language edges
codemap --dir src gpu-functions            # CUDA/Triton kernels
codemap --help                             # Full action list
```

## Languages

TypeScript, JavaScript, Python, Rust, Go, Java, Ruby, PHP, C, C++, CUDA, YAML/CMake

## Actions (42)

Run `codemap --help` for the full categorized list.
