use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::cmp::Reverse;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::types::Graph;

// ── Temporal Graph Analysis ────────────────────────────────────────
//
// Codemap's unique angle: the heterogeneous graph isn't just a
// snapshot — git history lets us treat the codebase as a sequence
// of graph states. Three actions here:
//
//   node-lifespan       per-file first-seen / last-seen / commit count
//   edge-churn          per-edge co-change counts across last N commits
//   community-evolution Leiden-style cluster tracking across N time
//                       snapshots, detecting birth/death/split/merge
//
// All three avoid expensive `git checkout` + reparse loops by working
// directly off `git log --name-status` and reconstructing snapshots
// virtually (filter graph to nodes whose first_seen ≤ snapshot).

#[derive(Debug, Clone)]
struct FileHistory {
    first_seen: i64,
    last_seen: i64,
    commits: usize,
}

fn now_ts() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Single git log pass that captures per-file first-seen, last-seen,
/// and commit count. Used by node-lifespan and community-evolution.
fn collect_histories(graph: &Graph) -> Result<HashMap<String, FileHistory>, String> {
    let output = Command::new("git")
        .args(["log", "--format=__C__%ct", "--name-status", "-M"])
        .current_dir(&graph.scan_dir)
        .output()
        .map_err(|e| format!("Failed to run git log: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            return Err("git log failed (not a git repo?)".to_string());
        }
        return Err(format!("git error: {stderr}"));
    }
    let text = String::from_utf8_lossy(&output.stdout);

    let mut h: HashMap<String, FileHistory> = HashMap::new();
    let mut current_ts: Option<i64> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("__C__") {
            current_ts = rest.trim().parse::<i64>().ok();
            continue;
        }
        let Some(ts) = current_ts else { continue };
        let line = line.trim_end();
        if line.is_empty() { continue; }
        // Status formats:
        //   "A\tpath" "M\tpath" "D\tpath"
        //   "R100\told\tnew"  "C75\told\tnew"
        let mut parts = line.split('\t');
        let status = match parts.next() { Some(s) => s, None => continue };
        let path = if status.starts_with('R') || status.starts_with('C') {
            // rename/copy: "Rxxx\told\tnew" — current path is the new one
            let _old = parts.next();
            match parts.next() { Some(p) => p, None => continue }
        } else {
            match parts.next() { Some(p) => p, None => continue }
        };
        if !graph.nodes.contains_key(path) { continue; }
        let entry = h.entry(path.to_string()).or_insert(FileHistory {
            first_seen: ts, last_seen: ts, commits: 0,
        });
        entry.first_seen = entry.first_seen.min(ts);
        entry.last_seen = entry.last_seen.max(ts);
        entry.commits += 1;
    }
    Ok(h)
}

// ── node-lifespan ───────────────────────────────────────────────────

pub fn node_lifespan(graph: &Graph, _target: &str) -> String {
    let histories = match collect_histories(graph) {
        Ok(h) => h,
        Err(e) => return e,
    };
    if histories.is_empty() {
        return "No git history found for any tracked file (untracked or shallow clone?).".to_string();
    }

    let now = now_ts();

    // Age buckets: [label, lo_seconds, hi_seconds_exclusive]
    let buckets: [(&str, i64, i64); 5] = [
        ("last week",    0,             7 * 86400),
        ("last month",   7 * 86400,     30 * 86400),
        ("last quarter", 30 * 86400,    90 * 86400),
        ("last year",    90 * 86400,    365 * 86400),
        ("> 1 year",     365 * 86400,   i64::MAX),
    ];

    let mut by_first = vec![0usize; buckets.len()];
    let mut by_last = vec![0usize; buckets.len()];
    for h in histories.values() {
        let af = (now - h.first_seen).max(0);
        let al = (now - h.last_seen).max(0);
        for (i, (_, lo, hi)) in buckets.iter().enumerate() {
            if af >= *lo && af < *hi { by_first[i] += 1; break; }
        }
        for (i, (_, lo, hi)) in buckets.iter().enumerate() {
            if al >= *lo && al < *hi { by_last[i] += 1; break; }
        }
    }

    // Young hotspots: < 1y old, sorted by commits-per-day
    let mut hot: Vec<(String, f64, usize)> = histories.iter()
        .filter(|(_, h)| now - h.first_seen < 365 * 86400)
        .map(|(id, h)| {
            let age_days = ((now - h.first_seen) as f64 / 86400.0).max(1.0);
            let velocity = h.commits as f64 / age_days;
            (id.clone(), velocity, h.commits)
        })
        .collect();
    hot.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Ancient stable: > 1y old AND > 90d since last touch
    let mut ancient: Vec<(String, FileHistory)> = histories.iter()
        .filter(|(_, h)| now - h.first_seen > 365 * 86400 && now - h.last_seen > 90 * 86400)
        .map(|(id, h)| (id.clone(), h.clone()))
        .collect();
    ancient.sort_by_key(|(_, h)| h.first_seen);

    // Active veterans: > 1y old AND touched recently (< 30d)
    let mut active_vets: Vec<(String, FileHistory)> = histories.iter()
        .filter(|(_, h)| now - h.first_seen > 365 * 86400 && now - h.last_seen < 30 * 86400)
        .map(|(id, h)| (id.clone(), h.clone()))
        .collect();
    active_vets.sort_by_key(|(_, h)| Reverse(h.commits));

    let mut lines = vec![
        format!("=== Node Lifespan ({} tracked files) ===", histories.len()),
        String::new(),
        "Files by first-appearance age:".to_string(),
    ];
    for (i, (label, _, _)) in buckets.iter().enumerate() {
        lines.push(format!("  {:<14} {}", label, by_first[i]));
    }
    lines.push(String::new());
    lines.push("Files by last-modified age:".to_string());
    for (i, (label, _, _)) in buckets.iter().enumerate() {
        lines.push(format!("  {:<14} {}", label, by_last[i]));
    }

    if !hot.is_empty() {
        lines.push(String::new());
        lines.push("Young hotspots (< 1y old, by commits/day):".to_string());
        for (id, v, c) in hot.iter().take(10) {
            lines.push(format!("  {:.3}/d  {:>3} commits  {}", v, c, id));
        }
    }
    if !active_vets.is_empty() {
        lines.push(String::new());
        lines.push("Active veterans (> 1y old, touched < 30d ago):".to_string());
        for (id, h) in active_vets.iter().take(10) {
            let age_y = (now - h.first_seen) as f64 / (365.0 * 86400.0);
            lines.push(format!("  {:.1}y  {:>3} commits  {}", age_y, h.commits, id));
        }
    }
    if !ancient.is_empty() {
        lines.push(String::new());
        lines.push("Ancient stable (> 1y old, dormant > 90d):".to_string());
        for (id, h) in ancient.iter().take(10) {
            let age_y = (now - h.first_seen) as f64 / (365.0 * 86400.0);
            lines.push(format!("  {:.1}y  {:>3} commits  {}", age_y, h.commits, id));
        }
    }

    lines.join("\n")
}

// ── edge-churn ──────────────────────────────────────────────────────

pub fn edge_churn(graph: &Graph, target: &str) -> String {
    let commit_count = if target.is_empty() {
        500usize
    } else {
        match target.parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => return format!("Usage: codemap edge-churn [N-commits]  (got: {target:?})"),
        }
    };

    let output = Command::new("git")
        .args(["log", "--format=%H", "--name-only", &format!("-{commit_count}")])
        .current_dir(&graph.scan_dir)
        .output();
    let log_text = match output {
        Ok(r) if r.status.success() => String::from_utf8_lossy(&r.stdout).to_string(),
        Ok(r) => return format!("git error: {}", String::from_utf8_lossy(&r.stderr).trim()),
        Err(e) => return format!("Failed to run git log: {e}"),
    };

    // Parse: each commit is a header line (40-hex) followed by file paths,
    // separated by blank lines.
    let mut commits: Vec<HashSet<String>> = Vec::new();
    let mut current: HashSet<String> = HashSet::new();
    for line in log_text.lines() {
        let line = line.trim();
        let is_header = line.len() == 40 && line.chars().all(|c| c.is_ascii_hexdigit());
        if is_header || line.is_empty() {
            if !current.is_empty() { commits.push(std::mem::take(&mut current)); }
        } else if graph.nodes.contains_key(line) {
            current.insert(line.to_string());
        }
    }
    if !current.is_empty() { commits.push(current); }

    if commits.is_empty() {
        return "No commits with tracked files found.".to_string();
    }

    // Build edge list from current graph (directed: importer → imported)
    let mut edges: Vec<(String, String)> = Vec::new();
    for (id, node) in &graph.nodes {
        for imp in &node.imports {
            if graph.nodes.contains_key(imp) && id != imp {
                edges.push((id.clone(), imp.clone()));
            }
        }
    }

    if edges.is_empty() {
        return "No import edges in graph.".to_string();
    }

    // For performance on large graphs: build per-file → set of commit indices,
    // then intersect for each edge.
    let mut file_to_commits: HashMap<&str, HashSet<usize>> = HashMap::new();
    for (i, c) in commits.iter().enumerate() {
        for f in c {
            file_to_commits.entry(f.as_str()).or_default().insert(i);
        }
    }

    let mut churn: HashMap<(String, String), usize> = HashMap::new();
    for (a, b) in &edges {
        let (Some(sa), Some(sb)) = (file_to_commits.get(a.as_str()), file_to_commits.get(b.as_str()))
            else { continue };
        let co = sa.intersection(sb).count();
        if co > 0 {
            churn.insert((a.clone(), b.clone()), co);
        }
    }

    let mut high: Vec<((String, String), usize)> = churn.iter()
        .map(|((a, b), v)| ((a.clone(), b.clone()), *v))
        .collect();
    high.sort_by_key(|(_, v)| Reverse(*v));

    let zero_count = edges.len() - churn.len();

    let mut lines = vec![
        format!("=== Edge Churn ({} edges, {} commits scanned) ===", edges.len(), commits.len()),
        format!("Edges with co-changes: {}", churn.len()),
        format!("Edges with zero co-changes (vestigial?): {}", zero_count),
        String::new(),
        "High co-change edges (true coupling):".to_string(),
    ];
    if high.is_empty() {
        lines.push("  (none)".to_string());
    } else {
        for ((a, b), v) in high.iter().take(20) {
            lines.push(format!("  {:>3}× {} → {}", v, a, b));
        }
    }

    // Sample zero-churn edges (where both files appear in history but never co-changed)
    let mut zero_with_history: Vec<&(String, String)> = edges.iter()
        .filter(|(a, b)| {
            !churn.contains_key(&(a.clone(), b.clone()))
                && file_to_commits.contains_key(a.as_str())
                && file_to_commits.contains_key(b.as_str())
        })
        .collect();
    zero_with_history.sort();
    if !zero_with_history.is_empty() {
        lines.push(String::new());
        lines.push("Vestigial edges (both files have history, never co-changed):".to_string());
        for (a, b) in zero_with_history.iter().take(15) {
            lines.push(format!("  {} → {}", a, b));
        }
        if zero_with_history.len() > 15 {
            lines.push(format!("  ... and {} more", zero_with_history.len() - 15));
        }
    }

    lines.join("\n")
}

// ── community-evolution ─────────────────────────────────────────────

pub fn community_evolution(graph: &Graph, target: &str) -> String {
    let n_buckets: usize = if target.is_empty() {
        4
    } else {
        match target.parse::<usize>() {
            Ok(n) if (2..=8).contains(&n) => n,
            _ => return format!("Usage: codemap community-evolution [N-snapshots, 2..8]  (got: {target:?})"),
        }
    };

    let histories = match collect_histories(graph) {
        Ok(h) => h,
        Err(e) => return e,
    };
    if histories.len() < 10 {
        return format!("Need ≥10 tracked files with git history (have {}).", histories.len());
    }

    let oldest = histories.values().map(|h| h.first_seen).min().unwrap();
    let now = now_ts();
    let span = (now - oldest).max(1);
    let step = span / n_buckets as i64;

    let snaps: Vec<i64> = (1..=n_buckets).map(|i| oldest + step * i as i64).collect();

    // Cluster each snapshot
    let snap_clusters: Vec<HashMap<String, String>> = snaps.iter()
        .map(|&cutoff| cluster_at_snapshot(graph, &histories, cutoff))
        .collect();

    let mut lines = vec![
        format!("=== Community Evolution ({} snapshots, {} files) ===", n_buckets, histories.len()),
        format!("Span: {}d ({} → {})", span / 86400, fmt_date(oldest), fmt_date(now)),
        String::new(),
    ];

    for i in 0..(snap_clusters.len() - 1) {
        let a = group_clusters(&snap_clusters[i], 3);
        let b = group_clusters(&snap_clusters[i + 1], 3);

        lines.push(format!("Snapshot {} → {} ({} clusters → {} clusters):",
            fmt_date(snaps[i]), fmt_date(snaps[i + 1]), a.len(), b.len()));

        let mut events_seen = false;

        // Births: b cluster with no a-predecessor (jaccard > threshold)
        for b_members in b.values() {
            let best = a.values()
                .map(|a_members| jaccard(a_members, b_members))
                .fold(0.0f64, f64::max);
            if best < 0.1 && b_members.len() >= 5 {
                lines.push(format!("  BIRTH:  +{} files (no predecessor, peak jacc={:.2})", b_members.len(), best));
                events_seen = true;
            }
        }
        // Deaths: a cluster with no b-successor
        for a_members in a.values() {
            let best = b.values()
                .map(|b_members| jaccard(a_members, b_members))
                .fold(0.0f64, f64::max);
            if best < 0.1 && a_members.len() >= 5 {
                lines.push(format!("  DEATH:  -{} files (no successor, peak jacc={:.2})", a_members.len(), best));
                events_seen = true;
            }
        }
        // Splits: a cluster maps to ≥2 b clusters with jaccard > 0.2
        for a_members in a.values() {
            let succ_count = b.values()
                .filter(|b_members| jaccard(a_members, b_members) > 0.2)
                .count();
            if succ_count >= 2 && a_members.len() >= 5 {
                lines.push(format!("  SPLIT:  cluster of {} → {} pieces", a_members.len(), succ_count));
                events_seen = true;
            }
        }
        // Merges: b cluster maps from ≥2 a clusters with jaccard > 0.2
        for b_members in b.values() {
            let pred_count = a.values()
                .filter(|a_members| jaccard(a_members, b_members) > 0.2)
                .count();
            if pred_count >= 2 && b_members.len() >= 5 {
                lines.push(format!("  MERGE:  {} predecessors → cluster of {}", pred_count, b_members.len()));
                events_seen = true;
            }
        }

        if !events_seen {
            lines.push("  (no major birth/death/split/merge events)".to_string());
        }
        lines.push(String::new());
    }

    // Per-snapshot top clusters (final state)
    let final_groups = group_clusters(&snap_clusters[snap_clusters.len() - 1], 3);
    let mut sorted_final: Vec<&HashSet<String>> = final_groups.values().collect();
    sorted_final.sort_by_key(|s| Reverse(s.len()));
    if !sorted_final.is_empty() {
        lines.push(format!("Final-snapshot top clusters ({}):", sorted_final.len()));
        for (i, members) in sorted_final.iter().take(5).enumerate() {
            let mut sample: Vec<&str> = members.iter().take(3).map(|s| s.as_str()).collect();
            sample.sort();
            lines.push(format!("  {}. {} files  e.g. {}", i + 1, members.len(), sample.join(", ")));
        }
    }

    lines.join("\n")
}

fn cluster_at_snapshot(graph: &Graph, histories: &HashMap<String, FileHistory>, cutoff: i64) -> HashMap<String, String> {
    let live: HashSet<String> = histories.iter()
        .filter(|(_, h)| h.first_seen <= cutoff)
        .map(|(id, _)| id.clone())
        .collect();

    if live.is_empty() {
        return HashMap::new();
    }

    // Build undirected adjacency restricted to live nodes
    let mut adj: HashMap<String, HashSet<String>> = HashMap::new();
    for id in &live {
        adj.entry(id.clone()).or_default();
        if let Some(node) = graph.nodes.get(id) {
            for imp in &node.imports {
                if live.contains(imp) {
                    adj.entry(id.clone()).or_default().insert(imp.clone());
                    adj.entry(imp.clone()).or_default().insert(id.clone());
                }
            }
        }
    }

    lpa_cluster(&live, &adj)
}

fn lpa_cluster(live: &HashSet<String>, adj: &HashMap<String, HashSet<String>>) -> HashMap<String, String> {
    let mut ids: Vec<String> = live.iter().cloned().collect();
    ids.sort();
    let mut labels: HashMap<String, String> = ids.iter().map(|id| (id.clone(), id.clone())).collect();

    let mut seed: u64 = (ids.len() as u64).wrapping_mul(2654435761);
    let mut next_rand = || -> f64 {
        seed = (seed.wrapping_mul(1664525).wrapping_add(1013904223)) & 0x7fffffff;
        seed as f64 / 0x7fffffff_u64 as f64
    };

    for _ in 0..15 {
        let mut changed = false;
        let mut shuffled = ids.clone();
        for i in (1..shuffled.len()).rev() {
            let j = (next_rand() * (i + 1) as f64) as usize;
            shuffled.swap(i, j);
        }
        for id in &shuffled {
            let neighbors = match adj.get(id) { Some(s) => s, None => continue };
            if neighbors.is_empty() { continue; }
            let mut counts: HashMap<&String, usize> = HashMap::new();
            for n in neighbors {
                if let Some(l) = labels.get(n) { *counts.entry(l).or_insert(0) += 1; }
            }
            let current = match labels.get(id) { Some(l) => l.clone(), None => continue };
            let mut best = current.clone();
            let mut best_c = 0usize;
            for (l, c) in &counts {
                if *c > best_c { best_c = *c; best = (*l).clone(); }
            }
            if best != current { labels.insert(id.clone(), best); changed = true; }
        }
        if !changed { break; }
    }
    labels
}

fn group_clusters(labels: &HashMap<String, String>, min_size: usize) -> HashMap<String, HashSet<String>> {
    let mut out: HashMap<String, HashSet<String>> = HashMap::new();
    for (id, c) in labels {
        out.entry(c.clone()).or_default().insert(id.clone());
    }
    out.retain(|_, members| members.len() >= min_size);
    out
}

fn jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
    let inter = a.intersection(b).count();
    let union = a.union(b).count();
    if union == 0 { 0.0 } else { inter as f64 / union as f64 }
}

fn fmt_date(ts: i64) -> String {
    // Cheap calendar conversion: civil-from-days (Howard Hinnant's
    // algorithm) converts unix seconds → YYYY-MM-DD without pulling
    // in a chrono dep.
    let days = ts.div_euclid(86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let yyyy = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", yyyy, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_date_known_values() {
        // Verified against `date -u -d @TS`:
        assert_eq!(fmt_date(0), "1970-01-01");
        assert_eq!(fmt_date(946684800), "2000-01-01");
        assert_eq!(fmt_date(1777507200), "2026-04-30");
        assert_eq!(fmt_date(1777680000), "2026-05-02");
        // Pre-epoch: civil_from_days handles negative day counts.
        assert_eq!(fmt_date(-86400), "1969-12-31");
    }

    #[test]
    fn jaccard_basic() {
        let a: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        let b: HashSet<String> = ["b", "c", "d"].iter().map(|s| s.to_string()).collect();
        assert!((jaccard(&a, &b) - 0.5).abs() < 1e-9);
        let empty: HashSet<String> = HashSet::new();
        assert_eq!(jaccard(&empty, &empty), 0.0);
    }

    #[test]
    fn lpa_isolates_disconnected_components() {
        let live: HashSet<String> = ["a", "b", "c", "d"].iter().map(|s| s.to_string()).collect();
        let mut adj: HashMap<String, HashSet<String>> = HashMap::new();
        adj.insert("a".to_string(), ["b".to_string()].into_iter().collect());
        adj.insert("b".to_string(), ["a".to_string()].into_iter().collect());
        adj.insert("c".to_string(), ["d".to_string()].into_iter().collect());
        adj.insert("d".to_string(), ["c".to_string()].into_iter().collect());
        let labels = lpa_cluster(&live, &adj);
        // a == b, c == d, but {a,b} != {c,d}
        assert_eq!(labels["a"], labels["b"]);
        assert_eq!(labels["c"], labels["d"]);
        assert_ne!(labels["a"], labels["c"]);
    }
}
