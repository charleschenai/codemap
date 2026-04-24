use clap::Parser;
use codemap_core::{ScanOptions, scan, execute, CodemapError};
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "codemap", version, about = "Codebase dependency analysis (47 actions, multi-repo)", after_help = "\
Actions:
  Analysis:     stats, trace, blast-radius, phone-home, coupling, dead-files,
                circular, exports/functions, callers, hotspots, size, layers, diff,
                orphan-exports, health, summary
  Navigation:   why, paths, subgraph, similar
  Graph Theory: pagerank, hubs, bridges, clusters, islands, dot, mermaid
  Functions:    call-graph, dead-functions, fn-info, diff-functions, complexity,
                import-cost, churn, api-diff, clones, git-coupling
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

    if json {
        let json_data = serde_json::json!({
            "action": action,
            "target": if target.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(target.to_string()) },
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
            // Get current time without chrono dependency
            let now = {
                let output = std::process::Command::new("date").arg("+%H:%M:%S").output();
                output.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default()
            };
            eprintln!("Every {}s: codemap {} {}  ({})\n", secs, cli.action, target, now);
            run_once(&dirs, &cli.include_paths, true, true, &cli.action, &target, cli.tree, cli.json);
            std::thread::sleep(std::time::Duration::from_secs(secs));
        }
    } else {
        if !run_once(&dirs, &cli.include_paths, cli.no_cache, cli.quiet, &cli.action, &target, cli.tree, cli.json) {
            process::exit(1);
        }
    }
}
