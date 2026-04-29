use clap::Parser;
use codemap_core::{ScanOptions, scan, execute, CodemapError};
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "codemap", version, about = "Codebase dependency analysis (88 actions, multi-repo)", after_help = "\
Actions:
  Analysis:     stats, trace, blast-radius, phone-home, coupling, dead-files,
                circular, exports/functions, callers, hotspots, size, layers, diff,
                orphan-exports, health, summary, decorators, rename, context
  Navigation:   why, paths, subgraph, similar, structure
  Graph Theory: pagerank, hubs, bridges, clusters, islands, dot, mermaid
  Functions:    call-graph, dead-functions, fn-info, diff-functions, complexity,
                import-cost, churn, api-diff, clones, git-coupling, risk,
                diff-impact, entry-points
  Data Flow:    data-flow, taint, slice, trace-value, sinks
  Security:     secret-scan, dep-tree, dead-deps, api-surface
  Cross-Lang:   lang-bridges, gpu-functions, monkey-patches, dispatch-map
  Reverse:      clarion-schema, pe-strings, pe-exports, pe-imports, pe-resources,
                pe-debug, dbf-schema, pe-sections, dotnet-meta, sql-extract,
                binary-diff
  Binary:       elf-info, macho-info, java-class, wasm-info
  Web:          web-api, web-dom, web-sitemap, web-blueprint, js-api-extract
  Comparison:   compare
  LSP:          lsp-symbols, lsp-references, lsp-calls, lsp-diagnostics, lsp-types
  Schemas:      proto-schema, openapi-schema, graphql-schema, docker-map, terraform-map

Languages: TS/JS, Python, Rust, Go, Java, Ruby, PHP, C/C++, CUDA, Bash/Shell")]
struct Cli {
    /// Directory to scan (repeatable for multi-repo)
    #[arg(long = "dir", value_name = "PATH")]
    dirs: Vec<PathBuf>,

    /// C/C++ include search path (repeatable)
    #[arg(long = "include-path", value_name = "PATH")]
    include_paths: Vec<PathBuf>,

    /// Output JSON instead of text
    #[arg(long)]
    json: bool,

    /// Show full dependency tree (data-flow actions)
    #[arg(long)]
    tree: bool,

    /// Force fresh scan (ignore .codemap/ cache)
    #[arg(long = "no-cache")]
    no_cache: bool,

    /// Watch mode: re-run every N seconds (default 2)
    #[arg(long, value_name = "SECS", num_args = 0..=1, default_missing_value = "2")]
    watch: Option<u64>,

    /// Suppress scan/cache status messages
    #[arg(short, long)]
    quiet: bool,

    /// The analysis action to perform
    action: String,

    /// Target argument (file, function, pattern, git ref)
    target: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
fn run_once(dirs: &[PathBuf], include_paths: &[PathBuf], no_cache: bool, quiet: bool, action: &str, target: &str, tree: bool, json: bool) -> bool {
    let options = ScanOptions {
        dirs: dirs.to_vec(),
        include_paths: include_paths.to_vec(),
        no_cache,
        quiet,
    };

    let mut graph = match scan(options) {
        Ok(g) => g,
        Err(e) => { eprintln!("Error: {e}"); return false; }
    };

    let result = match execute(&mut graph, action, target, tree) {
        Ok(r) => r,
        Err(CodemapError::UnknownAction(a)) => {
            eprintln!("Unknown action: {a}. Run 'codemap --help' for usage.");
            return false;
        }
        Err(e) => { eprintln!("Error: {e}"); return false; }
    };

    let is_error = result.starts_with("File not found:")
        || result.starts_with("No files")
        || result.starts_with("Usage:")
        || result.starts_with("Invalid git ref:");

    if json {
        let mut json_data = serde_json::json!({
            "ok": !is_error,
            "action": action,
            "target": if target.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(target.to_string()) },
            "files": graph.nodes.len(),
        });
        if is_error {
            json_data["error"] = serde_json::Value::String(result.clone());
        }
        json_data["result"] = serde_json::Value::String(result);
        println!("{}", serde_json::to_string_pretty(&json_data).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}")));
    } else {
        println!("{result}");
    }

    !is_error
}

fn main() {
    let cli = Cli::parse();
    let target = cli.target.join(" ");
    let dirs = if cli.dirs.is_empty() {
        vec![std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))]
    } else {
        cli.dirs
    };

    if let Some(interval) = cli.watch {
        let secs = if interval == 0 { 2 } else { interval };
        loop {
            // Clear screen
            print!("\x1b[2J\x1b[H");
            // Get current time using SystemTime
            let now = {
                let dur = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let total_secs = dur.as_secs();
                let h = (total_secs / 3600) % 24;
                let m = (total_secs / 60) % 60;
                let s = total_secs % 60;
                format!("{:02}:{:02}:{:02}", h, m, s)
            };
            eprintln!("Every {}s: codemap {} {}  ({})\n", secs, cli.action, target, now);
            run_once(&dirs, &cli.include_paths, cli.no_cache, cli.quiet, &cli.action, &target, cli.tree, cli.json);
            std::thread::sleep(std::time::Duration::from_secs(secs));
        }
    } else {
        if !run_once(&dirs, &cli.include_paths, cli.no_cache, cli.quiet, &cli.action, &target, cli.tree, cli.json) {
            process::exit(1);
        }
    }
}
