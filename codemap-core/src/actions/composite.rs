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
