use clap::Parser;
use codemap_core::{ScanOptions, scan, execute, CodemapError};
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "codemap", version, about = "Codebase dependency analysis (131 actions, heterogeneous graph, multi-repo)", after_help = "\
Actions:
  Analysis:     stats, trace, blast-radius, phone-home, coupling, dead-files,
                circular, exports/functions, callers, hotspots, size, layers, diff,
                orphan-exports, health, summary, decorators, rename, context
  Navigation:   why, paths, subgraph, similar, structure
  Graph Theory: pagerank, hubs, bridges, clusters [leiden|lpa], islands,
                dot, mermaid
  Centrality:   betweenness, eigenvector, katz, closeness, harmonic, load,
                structural-holes (alias: brokers), voterank, group,
                percolation, current-flow (alias: current-flow-betweenness),
                subgraph-centrality, second-order, dispersion, reaching,
                trophic, current-flow-closeness  (17 of NetworkX's 17)
                  (target = comma-separated kind filter, e.g. \"table,field\")
                  (group requires a kind filter; defines the node set)
  Algorithms:   bellman-ford <src>, astar <src> <tgt>, floyd-warshall,
                diameter, mst, cliques, kshortest <src> <tgt> [k],
                max-flow <src> <tgt>, feedback-arc
  Link prediction: jaccard, adamic-adar, common-neighbors
                  (top-30 unconnected pairs by similarity — surfaces
                   missing imports / refactor opportunities)
  Community:    clusters [leiden|lpa], k-core [k], k-clique [k],
                modularity-max, divisive
                  (Leiden default; k-core peels by degree;
                   modularity-max is greedy Clauset-Newman-Moore;
                   divisive is Girvan-Newman edge-betweenness)
  Heterogeneous: meta-path <kindA>-><kindB>[-><kindC>]
                  e.g. \"meta-path source->endpoint\" finds source files calling APIs
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
  ML/AI:        gguf-info, safetensors-info, onnx-info, pyc-info, cuda-info
  Composite:    validate, changeset, handoff, pipeline, audit
                  (pipeline target = comma-separated \"action:target\" entries)
                  (audit = composite report: chokepoints + brokers + clusters
                   + risk flagging + per-kind census)

Entity kinds (heterogeneous graph): source pe elf macho jclass wasm dll symbol
  endpoint form table field proto gql oapi docker tf model asm

Languages: TS/JS, Python, Rust, Go, Java, Ruby, PHP, C/C++, CUDA, Bash/Shell, C#, Kotlin, Lua, SQL")]
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
    // Auto-quiet the scanner for actions whose target is an explicit
    // existing file (pe-sections / bin-disasm / pyc-info / safetensors-info
    // / etc.). For these the scan dir is incidental and the "Scanned N
    // files" / "Cache: N/N unchanged" lines are visual noise.
    let scan_quiet = quiet
        || target.split_whitespace().next()
            .map(|t| std::path::Path::new(t).is_file())
            .unwrap_or(false);
    let options = ScanOptions {
        dirs: dirs.to_vec(),
        include_paths: include_paths.to_vec(),
        no_cache,
        quiet: scan_quiet,
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
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

        // Refuse to default-scan the user's home directory. A $HOME scan can
        // hit 192K+ files and OOM-kill the process — and on systemd, the
        // kernel will then reap the entire user@.service / tmux scope along
        // with it. Verified incident 2026-04-29 23:18 UTC.
        if let Ok(home) = std::env::var("HOME") {
            let home_path = PathBuf::from(&home);
            let allow = std::env::var("CODEMAP_NO_FILE_LIMIT")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if cwd == home_path && !allow {
                eprintln!(
                    "Refusing to scan $HOME ({}). Pass --dir <smaller_path> to scope the scan, \
                     or set CODEMAP_NO_FILE_LIMIT=1 to override.",
                    home
                );
                process::exit(2);
            }
        }

        // Skip the warning when target is an existing absolute file path —
        // for actions like pe-sections / bin-disasm / pyc-info / web-dom
        // / safetensors-info that operate on an explicit file, the scan
        // dir is incidental and the "no --dir" message is misleading.
        let target_is_explicit_file = target.split_whitespace().next()
            .map(|t| std::path::Path::new(t).is_file())
            .unwrap_or(false);
        if !cli.quiet && !target_is_explicit_file {
            eprintln!(
                "(no --dir given; defaulting to current directory: {})",
                cwd.display()
            );
        }
        vec![cwd]
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
