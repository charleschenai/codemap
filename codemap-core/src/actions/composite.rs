use crate::types::Graph;
use super::{analysis, functions, insights, security};

// ── 1. validate ────────────────────────────────────────────────────

pub fn validate(graph: &mut Graph, _target: &str) -> String {
    let mut lines = Vec::new();
    let mut failures = 0u32;
    let total_checks = 4u32;

    lines.push("=== Codemap Validate ===".to_string());
    lines.push(String::new());

    // 1) Health score
    let health_output = analysis::health(graph);
    let (health_score, health_grade) = parse_health_score(&health_output);
    let health_pass = health_score >= 60;
    if !health_pass { failures += 1; }
    lines.push(format!(
        "  Health:     {}/100 ({})     {} {}",
        health_score,
        health_grade,
        if health_pass { "\u{2713}" } else { "\u{2717}" },
        if health_pass { "PASS" } else { "FAIL (< 60)" },
    ));

    // 2) Circular dependencies
    let circular_output = analysis::circular(graph);
    let cycle_count = parse_cycle_count(&circular_output);
    let cycle_pass = cycle_count == 0;
    if !cycle_pass { failures += 1; }
    lines.push(format!(
        "  Cycles:     {:<15} {} {}",
        cycle_count,
        if cycle_pass { "\u{2713}" } else { "\u{2717}" },
        if cycle_pass { "PASS" } else { "FAIL" },
    ));

    // 3) Dead files
    let dead_output = analysis::dead_files(graph);
    let dead_count = parse_dead_file_count(&dead_output);
    let total_files = graph.nodes.len();
    let dead_pct = if total_files > 0 {
        (dead_count as f64 / total_files as f64) * 100.0
    } else {
        0.0
    };
    let dead_pass = dead_pct < 10.0;
    if !dead_pass { failures += 1; }
    lines.push(format!(
        "  Dead files: {} ({:.1}%){}  {} {}",
        dead_count,
        dead_pct,
        " ".repeat(6usize.saturating_sub(format!("{} ({:.1}%)", dead_count, dead_pct).len().saturating_sub(8))),
        if dead_pass { "\u{2713}" } else { "\u{2717}" },
        if dead_pass { "PASS (< 10%)" } else { "FAIL (>= 10%)" },
    ));

    // 4) Secret scan
    let secret_output = security::secret_scan(graph, "");
    let critical_secrets = parse_critical_secrets(&secret_output);
    let secret_pass = critical_secrets == 0;
    if !secret_pass { failures += 1; }
    lines.push(format!(
        "  Secrets:    {} critical{}     {} {}",
        critical_secrets,
        " ".repeat(4usize.saturating_sub(critical_secrets.to_string().len())),
        if secret_pass { "\u{2713}" } else { "\u{2717}" },
        if secret_pass { "PASS" } else { "FAIL" },
    ));

    lines.push(String::new());

    let passed = total_checks - failures;
    if failures == 0 {
        lines.push(format!("  Result: PASS ({}/{} checks)", passed, total_checks));
    } else {
        lines.push(format!("  Result: FAIL ({}/{} checks failed)", failures, total_checks));
    }

    lines.join("\n")
}

fn parse_health_score(output: &str) -> (u32, String) {
    // Look for "XX/100" pattern
    for line in output.lines() {
        if let Some(pos) = line.find("/100") {
            // Walk backwards to find digits
            let before = &line[..pos];
            let digits: String = before.chars().rev().take_while(|c| c.is_ascii_digit()).collect::<String>().chars().rev().collect();
            if let Ok(score) = digits.parse::<u32>() {
                let grade = match score {
                    90..=100 => "A",
                    80..=89 => "B",
                    70..=79 => "C",
                    60..=69 => "D",
                    _ => "F",
                };
                return (score, grade.to_string());
            }
        }
    }
    (0, "F".to_string())
}

fn parse_cycle_count(output: &str) -> usize {
    // Look for "N cycle" or "No circular" or count cycle entries
    if output.contains("No circular") || output.contains("0 cycle") {
        return 0;
    }
    // Count lines that look like cycle entries (numbered or with arrow patterns)
    let mut count = 0;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.contains(" -> ") || trimmed.contains(" → ") {
            count += 1;
        }
    }
    count
}

fn parse_dead_file_count(output: &str) -> usize {
    if output.contains("No dead files") || output.contains("0 dead") {
        return 0;
    }
    // Count non-header, non-empty lines as dead files
    let mut count = 0;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("===") || trimmed.starts_with("Dead") {
            continue;
        }
        if !trimmed.is_empty() {
            count += 1;
        }
    }
    count
}

fn parse_critical_secrets(output: &str) -> usize {
    if output.contains("No secrets found") || output.contains("0 findings") {
        return 0;
    }
    // Count lines containing "critical" or "CRITICAL"
    let mut count = 0;
    for line in output.lines() {
        let lower = line.to_lowercase();
        if lower.contains("critical") && !lower.contains("0 critical") {
            count += 1;
        }
    }
    // If no "critical" keyword found, count total findings
    if count == 0 {
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.contains("│") || trimmed.contains("|") {
                // Table row = a finding
                if !trimmed.contains("File") && !trimmed.contains("---") {
                    count += 1;
                }
            }
        }
    }
    count
}

// ── 2. changeset ───────────────────────────────────────────────────

pub fn changeset(graph: &mut Graph, target: &str) -> String {
    let git_ref = if target.is_empty() { "HEAD~1" } else { target };

    let mut lines = Vec::new();
    lines.push(format!("=== Changeset Analysis ({}) ===", git_ref));
    lines.push(String::new());

    // Risk score
    let risk_output = functions::risk(graph, git_ref);
    let risk_score = parse_risk_score(&risk_output);
    let risk_level = match risk_score {
        0..=30 => "LOW",
        31..=60 => "MEDIUM",
        61..=80 => "HIGH",
        _ => "CRITICAL",
    };
    lines.push(format!("  Risk: {}/100 ({})", risk_score, risk_level));

    // Diff output (files changed + blast radius)
    let diff_output = analysis::diff(graph, git_ref);
    let (files_changed, blast_radius, changed_files) = parse_diff_output(&diff_output);
    lines.push(format!("  Files changed: {}", files_changed));
    lines.push(format!("  Blast radius: {} files", blast_radius));

    // Function changes
    let fn_diff_output = functions::diff_functions(graph, git_ref);
    let (added, removed, modified) = parse_fn_changes(&fn_diff_output);
    lines.push(format!(
        "  Functions: +{} added, -{} removed, ~{} modified",
        added, removed, modified
    ));

    // Changed files section
    if !changed_files.is_empty() {
        lines.push(String::new());
        lines.push("\u{2500}\u{2500} Changed Files \u{2500}\u{2500}".to_string());
        for f in &changed_files {
            lines.push(format!("  {}", f));
        }
    }

    // Function change details
    if !fn_diff_output.is_empty()
        && !fn_diff_output.contains("No function changes")
        && !fn_diff_output.contains("No diff")
        && !fn_diff_output.contains("Invalid git ref")
    {
        lines.push(String::new());
        lines.push("\u{2500}\u{2500} Function Changes \u{2500}\u{2500}".to_string());
        for line in fn_diff_output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("===") || trimmed.starts_with("Function") {
                continue;
            }
            lines.push(format!("  {}", trimmed));
        }
    }

    // Churn hotspots
    let churn_output = functions::churn(graph, git_ref);
    if !churn_output.is_empty()
        && !churn_output.contains("No churn")
        && !churn_output.contains("Invalid git ref")
    {
        lines.push(String::new());
        lines.push("\u{2500}\u{2500} Churn Hotspots \u{2500}\u{2500}".to_string());
        let mut hotspot_count = 0;
        for line in churn_output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("===") || trimmed.starts_with("Churn") {
                continue;
            }
            if hotspot_count < 10 {
                lines.push(format!("  {}", trimmed));
                hotspot_count += 1;
            }
        }
    }

    lines.join("\n")
}

fn parse_risk_score(output: &str) -> u32 {
    // Look for "Risk: X/100" or "X/100" or just a number
    for line in output.lines() {
        if let Some(pos) = line.find("/100") {
            let before = &line[..pos];
            let digits: String = before
                .chars()
                .rev()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .chars()
                .rev()
                .collect();
            if let Ok(score) = digits.parse::<u32>() {
                return score;
            }
        }
    }
    0
}

fn parse_diff_output(output: &str) -> (usize, usize, Vec<String>) {
    let mut files_changed = 0;
    let mut blast_radius = 0;
    let mut changed_files = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("===") {
            continue;
        }
        let lower = trimmed.to_lowercase();
        if lower.contains("files changed") || lower.contains("changed files") {
            // Extract number
            for word in trimmed.split_whitespace() {
                if let Ok(n) = word.parse::<usize>() {
                    files_changed = n;
                    break;
                }
            }
        } else if lower.contains("blast") {
            for word in trimmed.split_whitespace() {
                if let Ok(n) = word.parse::<usize>() {
                    blast_radius = n;
                    break;
                }
            }
        } else if trimmed.starts_with("  ") || trimmed.starts_with("- ") || trimmed.contains('.') {
            // Looks like a file entry
            let file = trimmed.trim_start_matches("- ").trim();
            if !file.is_empty() && file.contains('/') {
                changed_files.push(file.to_string());
            }
        }
    }

    if files_changed == 0 {
        files_changed = changed_files.len();
    }

    (files_changed, blast_radius, changed_files)
}

fn parse_fn_changes(output: &str) -> (usize, usize, usize) {
    let mut added = 0;
    let mut removed = 0;
    let mut modified = 0;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('+') || trimmed.starts_with("added") {
            added += 1;
        } else if trimmed.starts_with('-') || trimmed.starts_with("removed") {
            removed += 1;
        } else if trimmed.starts_with('~') || trimmed.starts_with("modified") || trimmed.starts_with("changed") {
            modified += 1;
        }
    }

    (added, removed, modified)
}

// ── 3. handoff ─────────────────────────────────────────────────────

pub fn handoff(graph: &mut Graph, target: &str) -> String {
    // Default token budget
    let budget = if target.is_empty() { "8k" } else { target };

    let mut lines = Vec::new();
    lines.push("=== Codemap Handoff ===".to_string());
    lines.push(String::new());
    lines.push("# Project Briefing".to_string());
    lines.push(String::new());

    // Overview (stats)
    lines.push("## Overview".to_string());
    let stats_output = analysis::stats(graph);
    for line in stats_output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("===") {
            continue;
        }
        lines.push(trimmed.to_string());
    }
    lines.push(String::new());

    // Health
    let health_output = analysis::health(graph);
    let (score, grade) = parse_health_score(&health_output);
    lines.push(format!("## Health: {}/100 ({})", score, grade));
    lines.push(String::new());

    // Architecture Layers
    let layers_output = analysis::layers(graph);
    if !layers_output.is_empty() && !layers_output.contains("No layers") {
        lines.push("## Architecture Layers".to_string());
        for line in layers_output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("===") {
                continue;
            }
            lines.push(trimmed.to_string());
        }
        lines.push(String::new());
    }

    // Key Files (hotspots, top 10)
    let hotspots_output = analysis::hotspots(graph);
    if !hotspots_output.is_empty() && !hotspots_output.contains("No hotspots") {
        lines.push("## Key Files (by importance)".to_string());
        let mut count = 0;
        for line in hotspots_output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("===") || trimmed.starts_with("Hotspot") {
                continue;
            }
            if count < 10 {
                lines.push(trimmed.to_string());
                count += 1;
            }
        }
        lines.push(String::new());
    }

    // Dashboard summary
    let summary_output = insights::summary(graph);
    if !summary_output.is_empty() {
        lines.push("## Dashboard".to_string());
        for line in summary_output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("===") {
                continue;
            }
            lines.push(trimmed.to_string());
        }
        lines.push(String::new());
    }

    // Repo Map (token-budgeted context)
    let context_output = insights::context(graph, budget);
    if !context_output.is_empty() {
        lines.push("## Repo Map (token-budgeted)".to_string());
        for line in context_output.lines() {
            lines.push(line.to_string());
        }
        lines.push(String::new());
    }

    lines.push("---".to_string());
    lines.push("Generated by codemap v5.1.0".to_string());

    lines.join("\n")
}

// ── 4. pipeline ────────────────────────────────────────────────────
//
// Chain multiple actions in a single CLI invocation, accumulating graph
// mutations across them. Useful for one-shot heterogeneous workflows
// where cache persistence is overkill or you want determinism (no
// dependency on whatever's already in `.codemap/cache.bincode`).
//
// Syntax: `codemap pipeline "action1:target1,action2:target2,...,final:target"`
//
// Examples:
//   codemap pipeline "js-api-extract:src/,meta-path:source->endpoint"
//     → registers endpoints from JS bundles, then traces source→endpoint
//       paths in a single process. Output is the meta-path result.
//   codemap pipeline "pe-imports:foo.exe,pe-exports:foo.exe,pagerank:"
//     → builds full PeBinary/Dll/Symbol graph, ranks by pagerank.
//   codemap pipeline "clarion-schema:db.clw,sql-extract:app.exe,meta-path:source->table"
//     → schema + binary SQL extraction + cross-domain query.
//
// Errors halt the pipeline immediately and print the error chain;
// preceding actions' partial mutations remain in the graph (and cache,
// per persist_typed_nodes — which dispatch runs after this composite
// returns).

pub fn pipeline(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return concat!(
            "Usage: codemap pipeline \"action1:target1,action2:target2,...,final:target\"\n",
            "\n",
            "Each entry runs in order against the same graph. Final entry's output is\n",
            "what gets printed. Errors halt the pipeline.\n",
            "\n",
            "Examples:\n",
            "  codemap pipeline \"js-api-extract:src/,meta-path:source->endpoint\"\n",
            "  codemap pipeline \"pe-imports:foo.exe,pagerank:\"\n",
            "  codemap pipeline \"clarion-schema:db.clw,sql-extract:app.exe,meta-path:source->table\"\n"
        ).to_string();
    }

    // Parse the comma-separated entries. Each is `action:target` (target
    // may contain '/' or '-' but not the outer comma; an entry without
    // a colon is an action with empty target — useful for things like
    // `pagerank` that don't take a target).
    let entries: Vec<(String, String)> = target.split(',')
        .map(|e| {
            let e = e.trim();
            match e.find(':') {
                Some(i) => (e[..i].trim().to_string(), e[i+1..].trim().to_string()),
                None => (e.to_string(), String::new()),
            }
        })
        .filter(|(a, _)| !a.is_empty())
        .collect();

    if entries.is_empty() {
        return "pipeline: no actions specified".to_string();
    }

    let mut log = vec![
        format!("=== Pipeline ({} steps) ===", entries.len()),
        String::new(),
    ];
    let last_idx = entries.len() - 1;
    let mut final_output = String::new();

    for (i, (action, t)) in entries.iter().enumerate() {
        let step_label = format!("Step {}/{}: {} {}",
            i + 1, entries.len(), action, t);
        log.push(format!("→ {step_label}"));

        // Recursively dispatch — but call dispatch_inner directly to avoid
        // double-running persist_typed_nodes per step (the outer dispatch
        // call that invoked `pipeline` will persist once at the end).
        match super::dispatch_inner(graph, action, t, false) {
            Ok(out) => {
                if i == last_idx {
                    final_output = out;
                } else {
                    // Intermediate steps: just summarize
                    let summary = out.lines().take(2).collect::<Vec<_>>().join(" | ");
                    log.push(format!("    ✓ {summary}"));
                }
            }
            Err(e) => {
                log.push(format!("    ✗ pipeline halted: {e}"));
                log.push(String::new());
                log.push("(preceding steps' mutations remain in the graph and persist to cache)".to_string());
                return log.join("\n");
            }
        }
    }

    log.push(String::new());
    log.push("── Final output ──".to_string());
    log.push(String::new());
    log.push(final_output);
    log.join("\n")
}

// ── 5. audit ────────────────────────────────────────────────────────
//
// "Architectural risk audit" composite. Runs betweenness + structural-
// holes + Leiden clusters and synthesizes an overview report flagging:
//
//   - High-risk nodes: top of both betweenness AND brokers — they're
//     chokepoints AND brokers between clusters. Refactoring or removing
//     them ripples wide. These are the "load-bearing walls" of your code.
//   - Hot clusters: top-3 largest communities by node count. Shows the
//     dominant architectural blocs.
//   - Bridge nodes: top brokers (high effective_size) — your integration
//     surface, where unrelated kinds touch.
//
// The output is a quick-read 1-page summary, not raw scores. Use this
// before a refactor or when joining a new codebase to see where the
// blast-radius hotspots are.

pub fn audit(graph: &mut Graph, _target: &str) -> String {
    use std::collections::HashSet;

    let n = graph.nodes.len();
    if n == 0 {
        return "audit: graph is empty (run a scan first or pass --dir).".to_string();
    }

    let mut lines = vec![
        "=== Codemap Architectural Audit ===".to_string(),
        format!("Graph: {} nodes across {} kinds", n,
            graph.nodes.values().map(|node| node.kind).collect::<HashSet<_>>().len()),
        String::new(),
    ];

    // 1) Betweenness — top chokepoints
    let bt = super::centrality::betweenness(graph, &[]);
    let chokepoints = parse_top_lines(&bt, 10);
    lines.push("── Top chokepoints (betweenness) ──".to_string());
    if chokepoints.is_empty() {
        lines.push("  (none — graph too small or fully disconnected)".to_string());
    } else {
        for (score, name) in &chokepoints {
            lines.push(format!("  {score:>8}  {name}"));
        }
    }
    lines.push(String::new());

    // 2) Structural holes — top brokers
    let sh = super::centrality::structural_holes(graph, &[]);
    let brokers = parse_top_lines(&sh, 10);
    lines.push("── Top brokers (structural holes) ──".to_string());
    if brokers.is_empty() {
        lines.push("  (none — no nodes connect distinct clusters)".to_string());
    } else {
        for (score, name) in &brokers {
            lines.push(format!("  {score:>8}  {name}"));
        }
    }
    lines.push(String::new());

    // 3) Risk: nodes that appear in both top-10 lists
    let chokepoint_names: HashSet<&str> = chokepoints.iter().map(|(_, n)| n.as_str()).collect();
    let dual_risk: Vec<&str> = brokers.iter()
        .filter(|(_, n)| chokepoint_names.contains(n.as_str()))
        .map(|(_, n)| n.as_str())
        .collect();
    lines.push("── 🚨 High-risk nodes (chokepoint AND broker) ──".to_string());
    if dual_risk.is_empty() {
        lines.push("  (none — your graph has good separation between chokepoints and brokers)".to_string());
    } else {
        lines.push("  These are the architectural load-bearing walls. Changes here".to_string());
        lines.push("  ripple through both shortest paths and cross-cluster edges.".to_string());
        lines.push("  Treat as 'avoid surprise' nodes for refactors.".to_string());
        lines.push(String::new());
        for name in &dual_risk {
            lines.push(format!("    {name}"));
        }
    }
    lines.push(String::new());

    // 4) Top clusters via Leiden
    let cl = super::leiden::clusters_leiden(graph);
    let cluster_summary = parse_cluster_summary(&cl, 3);
    lines.push("── Dominant clusters (Leiden) ──".to_string());
    if cluster_summary.is_empty() {
        lines.push("  (none — graph too small for community detection)".to_string());
    } else {
        for (i, summary) in cluster_summary.iter().enumerate() {
            lines.push(format!("  #{}: {}", i + 1, summary));
        }
    }
    lines.push(String::new());

    // 5) Per-kind census
    let mut by_kind: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for node in graph.nodes.values() {
        *by_kind.entry(node.kind.as_str()).or_insert(0) += 1;
    }
    lines.push("── Node census by EntityKind ──".to_string());
    for (kind, count) in &by_kind {
        lines.push(format!("  {kind:<10}  {count}"));
    }

    lines.push(String::new());
    lines.push("Tip: drill into specific risk nodes with `codemap callers <name>` or".to_string());
    lines.push("`codemap subgraph <name>` to see what depends on them.".to_string());
    lines.join("\n")
}

/// Parse the top N (score, name) entries from a centrality report.
/// Reports look like:
///   `   0.1234  some/file.rs`
/// We just read each non-empty data line and grab the last whitespace
/// segment as the name, the rest as the score.
fn parse_top_lines(report: &str, n: usize) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in report.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("===") || line.starts_with("──")
            || line.starts_with("Filter:") || line.starts_with("Reading:") { continue; }
        // Expect: "score  name"
        let parts: Vec<&str> = line.splitn(2, char::is_whitespace).collect();
        if parts.len() != 2 { continue; }
        let score = parts[0].trim();
        // Skip header lines like "eff_size  constraint  node"
        if score.parse::<f64>().is_err() { continue; }
        let name = parts[1].trim_start();
        // For structural-holes the line has "score score name"
        let cols: Vec<&str> = name.splitn(2, char::is_whitespace).collect();
        let final_name = if cols.len() == 2 && cols[0].parse::<f64>().is_ok() {
            cols[1].trim().to_string()
        } else {
            name.to_string()
        };
        out.push((score.to_string(), final_name));
        if out.len() >= n { break; }
    }
    out
}

/// Parse the top N cluster summaries from a Leiden/LPA report. Each
/// cluster block starts with "Cluster N (X files, Y% internal coupling):"
fn parse_cluster_summary(report: &str, n: usize) -> Vec<String> {
    let mut out = Vec::new();
    for line in report.lines() {
        if line.starts_with("Cluster ") && line.contains(" files,") {
            out.push(line.trim().trim_end_matches(':').to_string());
            if out.len() >= n { break; }
        }
    }
    out
}
