// ── codemap think — natural-language goal router (5.25.0) ────────────
//
// With 163 actions, the AI (and humans) hit choice paralysis when picking
// the right pipeline for a goal. `think` is the one action that takes
// plain English, classifies the intent against a curated catalog of ~20
// common goals, and runs the matching pipeline. Output starts with the
// chosen pipeline so the user knows what was selected — and can run the
// constituent actions directly next time.
//
// Design notes:
//   - Keyword-match classifier (case-insensitive substring). v1 — fast,
//     deterministic, easy to test. Future v2 could embed-route or LLM-
//     classify, but the keyword table covers the 80% of asks well.
//   - Path detection: tokens in the goal that exist on disk become the
//     pipeline target. Otherwise we use the empty target (most actions
//     default to scan_dir).
//   - URL guard: any token starting with http:// or https:// is REJECTED
//     with a "passive only — feed me a captured artifact" message. This
//     enforces the no-active-network rule without relying on the user
//     remembering it.
//   - Pipeline runner calls `dispatch()` for each step — same code path
//     the CLI uses for explicit single-action invocations. No special
//     casing.
//   - Recursion guard: `think` never includes itself in any pipeline.

use crate::types::Graph;
use std::path::Path;

pub fn think(graph: &mut Graph, target: &str) -> String {
    if target.trim().is_empty() {
        return usage();
    }

    // Reject live-URL goals up front. codemap is pure-static; the user
    // must hand it a captured artifact (HAR, downloaded HTML, sitemap.xml,
    // crt.sh JSON, etc.). This preserves the no-active-network invariant.
    for tok in target.split_whitespace() {
        if tok.starts_with("http://") || tok.starts_with("https://") {
            return format!(
                "{}\n\n\
                codemap is a pure-static analyzer — it never makes network requests. \
                For website analysis, capture the artifact first then point `think` at it:\n\n  \
                  curl -o /tmp/index.html '{tok}'\n  \
                  codemap think \"recon /tmp/index.html\"\n\n\
                Or for full JS-rendered captures, use Playwright/Burp/wget to record a HAR \
                and feed that. See README \"Active recon belongs in separate tools\" section.",
                rejected_url_banner(tok),
            );
        }
    }

    let goal = target.trim();
    let detected_path = detect_path_in(goal);
    let intent = classify_goal(goal);
    let pipeline = pipeline_for(intent, &detected_path);

    let mut out = String::new();
    out.push_str(&format!("=== codemap think ({intent:?}) ===\n\n"));
    out.push_str(&format!("Goal:     {goal}\n"));
    out.push_str(&format!("Intent:   {} — {}\n", intent.label(), intent.rationale()));
    if let Some(p) = &detected_path {
        out.push_str(&format!("Target:   {p}\n"));
    } else {
        out.push_str("Target:   (scan dir — see --dir)\n");
    }
    out.push_str("Pipeline: ");
    let pipeline_summary = pipeline.iter()
        .map(|step| step.action.to_string())
        .collect::<Vec<_>>()
        .join(" → ");
    out.push_str(&pipeline_summary);
    out.push_str("\n\n");

    if matches!(intent, Intent::Fallback) {
        out.push_str(&fallback_guidance(goal));
        return out;
    }

    for step in &pipeline {
        out.push_str(&format!("── {} ──\n", step.action));
        match super::dispatch(graph, step.action, &step.target, false) {
            Ok(s) => {
                out.push_str(&s);
                out.push_str("\n\n");
            }
            Err(e) => {
                out.push_str(&format!("(skipped: {e})\n\n"));
            }
        }
    }

    out.push_str("──\n");
    out.push_str(&format!(
        "Pipeline above corresponds to: {}\nNext time skip `think` and run them directly if you want finer control.\n",
        pipeline_summary,
    ));
    out
}

// ── Intent enum ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    CodebaseAudit,
    LoadBearing,
    SecurityReview,
    FindSecrets,
    SupplyChain,
    DeadCode,
    Hotspots,
    Structure,
    ReversePe,
    ReverseElf,
    ReverseMacho,
    AndroidApk,
    MlModel,
    WebRecon,
    FindEndpoints,
    DiffBinaries,
    GraphLayout,
    Fallback,
}

impl Intent {
    fn label(self) -> &'static str {
        match self {
            Intent::CodebaseAudit => "codebase audit",
            Intent::LoadBearing   => "find load-bearing files",
            Intent::SecurityReview => "security review",
            Intent::FindSecrets    => "hardcoded secrets",
            Intent::SupplyChain    => "supply chain / SBOM",
            Intent::DeadCode       => "dead code",
            Intent::Hotspots       => "git-history hotspots",
            Intent::Structure      => "codebase structure",
            Intent::ReversePe      => "reverse engineer PE binary",
            Intent::ReverseElf     => "reverse engineer ELF binary",
            Intent::ReverseMacho   => "reverse engineer Mach-O binary",
            Intent::AndroidApk     => "Android APK analysis",
            Intent::MlModel        => "ML model architecture",
            Intent::WebRecon       => "passive website recon (captured artifact)",
            Intent::FindEndpoints  => "HTTP endpoint discovery",
            Intent::DiffBinaries   => "diff two binaries",
            Intent::GraphLayout    => "render graph for visualization",
            Intent::Fallback       => "no clear match",
        }
    }
    fn rationale(self) -> &'static str {
        match self {
            Intent::CodebaseAudit  => "one-page architectural risk overview",
            Intent::LoadBearing    => "find chokepoints + brokers (dual-risk = load-bearing walls)",
            Intent::SecurityReview => "secrets + deps + API surface in one pass",
            Intent::FindSecrets    => "scan + promote each finding to a Secret graph node",
            Intent::SupplyChain    => "license scan + dep tree + (optional) CVE match",
            Intent::DeadCode       => "unused files + functions + dependencies",
            Intent::Hotspots       => "files with high recent churn or import-graph centrality",
            Intent::Structure      => "high-level layout + insights summary",
            Intent::ReversePe      => "imports + exports + strings + Rich/TLS + disasm + sections",
            Intent::ReverseElf     => "ELF info + strings + disasm",
            Intent::ReverseMacho   => "Mach-O info + load commands + dylib graph",
            Intent::AndroidApk     => "ZIP walk + manifest + DEX methods + permission heuristics",
            Intent::MlModel        => "header + tensors as graph nodes + (ONNX) operators",
            Intent::WebRecon       => "static parse of captured artifacts (HTML / HAR / sitemap / crt.sh / robots.txt)",
            Intent::FindEndpoints  => "API surface scan + meta-path source→endpoint",
            Intent::DiffBinaries   => "cross-graph binary-diff under diff:{session}: namespace",
            Intent::GraphLayout    => "DOT or Mermaid export for piping into visualizer",
            Intent::Fallback       => "couldn't pick a pipeline — see suggestions",
        }
    }
}

// ── Goal classifier ──────────────────────────────────────────────────

/// Substring keyword classifier. Order matters when keywords overlap —
/// more specific intents come first so e.g. "android apk" doesn't fall
/// through to the generic "audit" intent.
pub fn classify_goal(goal: &str) -> Intent {
    let g = goal.to_ascii_lowercase();
    let any = |patterns: &[&str]| patterns.iter().any(|p| g.contains(p));

    // Specific intents first.
    if any(&["apk", "android app", ".apk", "android binary"]) { return Intent::AndroidApk; }
    if any(&["diff", "compare two", "compare binaries", "what changed between"]) {
        // Only count as DiffBinaries if there are 2+ existing paths in the goal.
        let path_count = goal.split_whitespace()
            .filter(|t| Path::new(t).exists() && Path::new(t).is_file())
            .count();
        if path_count >= 2 { return Intent::DiffBinaries; }
    }
    if any(&[".exe", ".dll", "windows binary", "pe binary", "reverse pe", "reverse a windows"]) {
        return Intent::ReversePe;
    }
    if any(&[".so ", ".so\"", ".so'", "elf binary", "linux binary", "reverse elf", "reverse a linux"])
        || g.ends_with(".so")
    {
        return Intent::ReverseElf;
    }
    if any(&[".dylib", "macho", "mach-o", "mac binary", "reverse a mac"]) {
        return Intent::ReverseMacho;
    }
    if any(&[".gguf", ".onnx", ".safetensors", "ml model", "model architecture",
              "tensors", "onnx graph", "neural network"]) {
        return Intent::MlModel;
    }
    if any(&["recon", "website", "passive recon", "fingerprint site", "web stack",
              ".har", "sitemap", "crt.sh", "robots.txt"]) {
        return Intent::WebRecon;
    }
    if any(&["endpoint", "routes", "api surface", "what apis", "rest api"]) {
        return Intent::FindEndpoints;
    }
    if any(&["secrets", "credentials", "leaked keys", "api keys", "password leak"]) {
        return Intent::FindSecrets;
    }
    if any(&["security review", "security audit", "security check", "security pass"]) {
        return Intent::SecurityReview;
    }
    if any(&["supply chain", "sbom", "license scan", "dependencies report", "vulnerable deps",
              "cve", "spdx", "cyclonedx"]) {
        return Intent::SupplyChain;
    }
    if any(&["dead code", "unused", "cleanup", "dead files", "dead deps"]) {
        return Intent::DeadCode;
    }
    if any(&["hotspot", "churn", "active files", "recently changed", "git history"]) {
        return Intent::Hotspots;
    }
    if any(&["load bearing", "load-bearing", "critical files", "important files",
              "bottleneck", "chokepoint"]) {
        return Intent::LoadBearing;
    }
    if any(&["dot", "mermaid", "gephi", "visualize", "render graph", "graph layout"]) {
        return Intent::GraphLayout;
    }
    if any(&["audit", "review codebase", "code review", "review the code", "analyze codebase",
              "overview of the codebase"]) {
        return Intent::CodebaseAudit;
    }
    if any(&["structure", "what is this", "what does this do", "summarize",
              "high-level overview", "what's in this repo", "explain"]) {
        return Intent::Structure;
    }
    Intent::Fallback
}

// ── Pipeline builder ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PipelineStep {
    pub action: &'static str,
    pub target: String,
}

fn step(action: &'static str, target: impl Into<String>) -> PipelineStep {
    PipelineStep { action, target: target.into() }
}

fn pipeline_for(intent: Intent, target_path: &Option<String>) -> Vec<PipelineStep> {
    let t = target_path.clone().unwrap_or_default();
    match intent {
        Intent::CodebaseAudit => vec![
            step("audit", ""),
            step("summary", ""),
        ],
        Intent::LoadBearing => vec![
            step("audit", ""),
            step("betweenness", ""),
            step("bridges", ""),
        ],
        Intent::SecurityReview => vec![
            step("secret-scan", ""),
            step("dep-tree", ""),
            step("dead-deps", ""),
            step("api-surface", ""),
        ],
        Intent::FindSecrets => vec![
            step("secret-scan", ""),
            step("pagerank", "secret"),
        ],
        Intent::SupplyChain => vec![
            step("license-scan", ""),
            step("dep-tree", ""),
            step("dead-deps", ""),
        ],
        Intent::DeadCode => vec![
            step("dead-files", ""),
            step("dead-functions", ""),
            step("dead-deps", ""),
        ],
        Intent::Hotspots => vec![
            step("hotspots", ""),
            step("churn", ""),
            step("git-coupling", ""),
        ],
        Intent::Structure => vec![
            step("structure", ""),
            step("summary", ""),
            step("layers", ""),
        ],
        Intent::ReversePe => vec![
            step("pe-meta",      t.clone()),
            step("pe-imports",   t.clone()),
            step("pe-exports",   t.clone()),
            step("pe-strings",   t.clone()),
            step("pe-sections",  t.clone()),
            step("pe-debug",     t.clone()),
            step("bin-disasm",   t),
        ],
        Intent::ReverseElf => vec![
            step("elf-info",   t.clone()),
            step("bin-disasm", t),
        ],
        Intent::ReverseMacho => vec![
            step("macho-info", t),
        ],
        Intent::AndroidApk => vec![
            step("apk-info", t),
            // Note: bin-disasm on each native lib is left to the user —
            // auto-disasm of every .so in lib/{abi}/ would balloon on
            // multi-ABI APKs. After this runs they can pick the libs to
            // explicitly disasm.
        ],
        Intent::MlModel => {
            // Dispatch by extension. If we can't tell, run all four.
            let lower = t.to_ascii_lowercase();
            let info_action = if lower.ends_with(".gguf") { "gguf-info" }
                else if lower.ends_with(".safetensors") { "safetensors-info" }
                else if lower.ends_with(".onnx") { "onnx-info" }
                else if lower.ends_with(".pyc") { "pyc-info" }
                else if lower.ends_with(".cubin") || lower.ends_with(".fatbin") { "cuda-info" }
                else { "gguf-info" };  // best-guess fallback
            vec![
                step(info_action, t),
                step("pagerank", "tensor"),
            ]
        }
        Intent::WebRecon => {
            // The captured artifact may be HTML, HAR, sitemap.xml, robots.txt,
            // crt.sh JSON. Dispatch by extension where we can; otherwise run
            // the parsers most likely to produce useful output.
            let lower = t.to_ascii_lowercase();
            if lower.ends_with("robots.txt") {
                vec![step("robots-parse", t)]
            } else if lower.ends_with("sitemap.xml") || lower.ends_with("sitemap.xml.gz") {
                vec![step("web-sitemap-parse", t)]
            } else if lower.ends_with(".har") {
                vec![
                    step("web-blueprint", t.clone()),
                    step("web-fingerprint", t),
                ]
            } else if lower.ends_with(".html") || lower.ends_with(".htm") {
                vec![
                    step("web-dom",         t.clone()),
                    step("web-fingerprint", t),
                ]
            } else if lower.ends_with(".json") && lower.contains("crt") {
                vec![step("crt-parse", t)]
            } else if t.is_empty() {
                // No artifact — emit guidance instead of running a pipeline.
                vec![]
            } else {
                vec![
                    step("web-dom",         t.clone()),
                    step("web-fingerprint", t),
                ]
            }
        }
        Intent::FindEndpoints => vec![
            step("api-surface", ""),
            step("meta-path", "source->endpoint"),
        ],
        Intent::DiffBinaries => {
            // We need to extract two paths from the goal string for binary-diff.
            let paths: Vec<&str> = target_path_pair(&t);
            if paths.len() == 2 {
                vec![step("binary-diff", format!("{} {}", paths[0], paths[1]))]
            } else {
                vec![]
            }
        }
        Intent::GraphLayout => vec![
            step("dot", ""),
        ],
        Intent::Fallback => vec![],
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Walk the goal tokens and return the first one that exists on disk.
/// Used as the pipeline target. Returns None if no token is a real path.
fn detect_path_in(goal: &str) -> Option<String> {
    for tok in goal.split_whitespace() {
        // Trim common surrounding punctuation that humans add ("foo.exe.")
        let clean = tok.trim_matches(|c: char| c == '.' || c == ',' || c == ';' || c == ':');
        if clean.is_empty() { continue; }
        if Path::new(clean).exists() {
            return Some(clean.to_string());
        }
    }
    None
}

/// Used by DiffBinaries — accepts a single string that may itself contain
/// two paths or just be the first path. Returns up to two existing paths.
fn target_path_pair(target: &str) -> Vec<&str> {
    target.split_whitespace()
        .filter(|t| Path::new(t).exists() && Path::new(t).is_file())
        .take(2)
        .collect()
}

fn rejected_url_banner(url: &str) -> String {
    format!("=== codemap think (rejected — live URL) ===\n\nGoal contains a live URL: {url}")
}

fn usage() -> String {
    "\
Usage: codemap think \"<goal in plain English>\"

Examples:
  codemap think \"audit this codebase\"
  codemap think \"find load-bearing files\"
  codemap think \"security review\"
  codemap think \"hardcoded secrets\"
  codemap think \"reverse this windows binary /path/to/app.exe\"
  codemap think \"android apk /path/to/app.apk\"
  codemap think \"recon /tmp/captured.html\"
  codemap think \"compare /tmp/v1.exe /tmp/v2.exe\"

The goal string is keyword-classified into one of ~18 intent buckets,
each mapped to a curated action pipeline. For website work, capture
the artifact first (curl/playwright/burp); codemap never makes network
requests.
".to_string()
}

fn fallback_guidance(goal: &str) -> String {
    format!("\
Couldn't classify goal: \"{goal}\"

Closest intents you can try:
  codemap think \"audit this codebase\"           — high-level architectural risk overview
  codemap think \"security review\"               — secrets + deps + API surface
  codemap think \"reverse <path/to/binary>\"      — full RE pipeline (PE/ELF/Mach-O)
  codemap think \"android apk <path/to/app.apk>\" — APK + DEX + permission heuristics
  codemap think \"recon <path/to/capture.html>\"  — passive web analysis on captured artifact
  codemap think \"find load-bearing files\"       — chokepoints + brokers
  codemap think \"dead code\"                     — unused files / functions / deps

Or pick a specific action — see `codemap --help` for the full list of 163 actions
(audit / pagerank / fiedler / meta-path / pe-imports / etc.).
")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_goal_covers_common_intents() {
        assert_eq!(classify_goal("audit this codebase"),               Intent::CodebaseAudit);
        assert_eq!(classify_goal("find LOAD-BEARING files"),           Intent::LoadBearing);
        assert_eq!(classify_goal("security review please"),            Intent::SecurityReview);
        assert_eq!(classify_goal("hardcoded secrets in this repo"),    Intent::FindSecrets);
        assert_eq!(classify_goal("supply chain audit"),                Intent::SupplyChain);
        assert_eq!(classify_goal("dead code cleanup"),                 Intent::DeadCode);
        assert_eq!(classify_goal("git history hotspots"),              Intent::Hotspots);
        assert_eq!(classify_goal("what is this codebase about"),       Intent::Structure);
        assert_eq!(classify_goal("reverse this windows binary"),       Intent::ReversePe);
        assert_eq!(classify_goal("look at /opt/app/foo.dll"),          Intent::ReversePe);
        assert_eq!(classify_goal("look at /opt/app/foo.dylib"),        Intent::ReverseMacho);
        assert_eq!(classify_goal("analyze libapp.so"),                 Intent::ReverseElf);
        assert_eq!(classify_goal("android apk /tmp/app.apk"),          Intent::AndroidApk);
        assert_eq!(classify_goal("ml model /tmp/llama.gguf"),          Intent::MlModel);
        assert_eq!(classify_goal("recon /tmp/captured.html"),          Intent::WebRecon);
        assert_eq!(classify_goal("find all api endpoints"),            Intent::FindEndpoints);
        assert_eq!(classify_goal("render graph as mermaid"),           Intent::GraphLayout);
    }

    #[test]
    fn classify_goal_falls_back_when_no_keywords_match() {
        assert_eq!(classify_goal("xyzzy plugh"), Intent::Fallback);
        assert_eq!(classify_goal(""), Intent::Fallback);
    }

    #[test]
    fn detect_path_in_finds_existing_files() {
        // /tmp exists on every Unix-like system the test runs on.
        let p = detect_path_in("audit /tmp please");
        assert_eq!(p.as_deref(), Some("/tmp"));
        // Trailing punctuation stripped.
        let p = detect_path_in("audit /tmp,");
        assert_eq!(p.as_deref(), Some("/tmp"));
        // Nothing existing → None.
        let p = detect_path_in("audit /nonexistent/path/foo.bar");
        assert!(p.is_none());
    }

    #[test]
    fn live_urls_are_rejected_with_passive_only_message() {
        // think requires &mut Graph; minimal one suffices.
        use crate::types::Graph;
        let mut g = Graph {
            nodes: std::collections::HashMap::new(),
            scan_dir: ".".to_string(),
            cpg: None,
        };
        let out = think(&mut g, "recon https://example.com/whatever");
        assert!(out.contains("rejected") || out.contains("never makes network requests"),
            "URL must be rejected: {out}");
        // No graph nodes should leak from the rejected path.
        assert!(g.nodes.is_empty());
    }

    #[test]
    fn empty_goal_returns_usage() {
        use crate::types::Graph;
        let mut g = Graph {
            nodes: std::collections::HashMap::new(),
            scan_dir: ".".to_string(),
            cpg: None,
        };
        let out = think(&mut g, "");
        assert!(out.contains("Usage: codemap think"));
        assert!(out.contains("Examples:"));
    }
}
