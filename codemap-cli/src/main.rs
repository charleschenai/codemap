use clap::Parser;
use codemap_core::{ScanOptions, scan, execute, CodemapError};
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "codemap", version, about = "Codebase dependency analysis (44 actions, multi-repo)", after_help = "\
Actions:
  Analysis:     stats, trace, blast-radius, phone-home, coupling, dead-files,
                circular, exports/functions, callers, hotspots, size, layers, diff,
                orphan-exports, health
  Navigation:   why, paths, subgraph, similar
  Graph Theory: pagerank, hubs, bridges, clusters, islands, dot, mermaid
  Functions:    call-graph, dead-functions, fn-info, diff-functions, complexity,
                import-cost, churn, api-diff
  Data Flow:    data-flow, taint, slice, trace-value, sinks
  Cross-Lang:   lang-bridges, gpu-functions, monkey-patches, dispatch-map
  Comparison:   compare")]
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

    /// The analysis action to perform
    action: String,

    /// Target argument (file, function, pattern, git ref)
    target: Vec<String>,
}

fn main() {
    let cli = Cli::parse();
    let target = cli.target.join(" ");
    let dirs = if cli.dirs.is_empty() {
        vec![std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))]
    } else {
        cli.dirs
    };

    let options = ScanOptions {
        dirs,
        include_paths: cli.include_paths,
        no_cache: cli.no_cache,
    };

    let mut graph = match scan(options) {
        Ok(g) => g,
        Err(e) => { eprintln!("Error: {e}"); process::exit(1); }
    };

    let result = match execute(&mut graph, &cli.action, &target, cli.tree) {
        Ok(r) => r,
        Err(CodemapError::UnknownAction(a)) => {
            eprintln!("Unknown action: {a}. Run 'codemap --help' for usage.");
            process::exit(1);
        }
        Err(e) => { eprintln!("Error: {e}"); process::exit(1); }
    };

    if cli.json {
        let json_data = serde_json::json!({
            "action": cli.action,
            "target": if target.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(target) },
            "files": graph.nodes.len(),
            "result": result,
        });
        println!("{}", serde_json::to_string_pretty(&json_data).unwrap());
    } else {
        println!("{result}");
    }

    let is_error = result.starts_with("File not found:")
        || result.starts_with("No files")
        || result.starts_with("Usage:")
        || result.starts_with("Invalid git ref:");
    if is_error { process::exit(1); }
}
