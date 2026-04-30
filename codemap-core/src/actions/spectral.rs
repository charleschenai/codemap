use std::collections::HashMap;
use crate::types::Graph;

// ── Spectral Graph Analysis ────────────────────────────────────────
//
// Three actions backed by an iterative Lanczos eigensolver on the
// graph Laplacian. No external linalg dep — full re-orthogonalization
// keeps Lanczos stable up to k≈60, which covers everything we
// actually compute (Fiedler vector = 2nd-smallest eigenpair;
// spectral clustering = first k smallest; spectral gap = first
// 20-30).
//
//   fiedler             algebraic connectivity λ₂ + Fiedler vector +
//                       natural sign-cut bisection (Fiedler 1973,
//                       Pothen-Simon-Liou 1990)
//   spectral-cluster k  Shi-Malik 2000: project nodes via top-k
//                       smallest eigenvectors of the normalized
//                       Laplacian, then k-means in that embedding
//   spectral-gap        eigenvalue spectrum + auto-detected community
//                       count from the largest eigenvalue gap (the
//                       "eigengap heuristic" of von Luxburg 2007)
//
// L = D - A (combinatorial Laplacian). The smallest eigenvalue of L
// is always 0 with eigenvector 𝟙. λ₂ is the algebraic connectivity:
// 0 ⇒ disconnected; small ⇒ near-bottleneck. Its eigenvector v₂ is
// the "Fiedler vector" — sign-of-coordinate gives the spectral
// bisection (the cut that approximately minimizes Cheeger's
// constant).

const MAX_NODES: usize = 5000;
const LANCZOS_MAX_K: usize = 60;
const LANCZOS_TOL: f64 = 1e-10;
const JACOBI_TOL: f64 = 1e-12;
const JACOBI_MAX_SWEEPS: usize = 60;

/// Sparse undirected Laplacian. Entries are unweighted.
struct Lap {
    n: usize,
    deg: Vec<f64>,
    nbr: Vec<Vec<usize>>,
    ids: Vec<String>,
}

fn build_lap(graph: &Graph) -> Result<Lap, String> {
    let mut ids: Vec<String> = graph.nodes.keys().cloned().collect();
    ids.sort();
    let n = ids.len();
    if n == 0 { return Err("Empty graph.".to_string()); }
    if n > MAX_NODES {
        return Err(format!("Graph has {n} nodes (max {MAX_NODES} for spectral analysis). Use clusters / leiden instead."));
    }
    let idx: HashMap<&str, usize> = ids.iter().enumerate().map(|(i, s)| (s.as_str(), i)).collect();
    let mut nbr_set: Vec<std::collections::HashSet<usize>> = vec![std::collections::HashSet::new(); n];
    for (i, id) in ids.iter().enumerate() {
        if let Some(node) = graph.nodes.get(id) {
            for imp in &node.imports {
                if let Some(&j) = idx.get(imp.as_str()) {
                    if i != j { nbr_set[i].insert(j); nbr_set[j].insert(i); }
                }
            }
        }
    }
    let nbr: Vec<Vec<usize>> = nbr_set.into_iter().map(|s| s.into_iter().collect()).collect();
    let deg: Vec<f64> = nbr.iter().map(|v| v.len() as f64).collect();
    Ok(Lap { n, deg, nbr, ids })
}

/// y = L · x where L = D - A (combinatorial Laplacian).
fn mat_vec(lap: &Lap, x: &[f64]) -> Vec<f64> {
    let n = lap.n;
    let mut y = vec![0.0; n];
    for i in 0..n {
        y[i] = lap.deg[i] * x[i];
        for &j in &lap.nbr[i] {
            y[i] -= x[j];
        }
    }
    y
}

/// y = L_sym · x where L_sym = I - D^(-1/2) A D^(-1/2) (symmetric
/// normalized Laplacian, used for Shi-Malik spectral clustering).
/// Isolated nodes (deg=0) are mapped to 0 to keep the operator well-defined.
fn mat_vec_norm(lap: &Lap, x: &[f64]) -> Vec<f64> {
    let n = lap.n;
    let mut y = vec![0.0; n];
    for i in 0..n {
        if lap.deg[i] == 0.0 { continue; }
        y[i] = x[i];
        let di_inv_sqrt = 1.0 / lap.deg[i].sqrt();
        let mut s = 0.0;
        for &j in &lap.nbr[i] {
            if lap.deg[j] == 0.0 { continue; }
            s += x[j] / lap.deg[j].sqrt();
        }
        y[i] -= di_inv_sqrt * s;
    }
    y
}

/// Lanczos with full re-orthogonalization. Operator is `op(&[f64]) -> Vec<f64>`.
/// Returns (alphas, betas, q_basis) where T = tridiag(alphas, betas) and
/// q_basis is the column-stored Lanczos basis (Vec of vectors, length k_iters+1).
fn lanczos<F: Fn(&[f64]) -> Vec<f64>>(n: usize, k_max: usize, op: F, seed: u64) -> (Vec<f64>, Vec<f64>, Vec<Vec<f64>>) {
    let k = k_max.min(n);
    let mut alphas: Vec<f64> = Vec::with_capacity(k);
    let mut betas: Vec<f64> = Vec::with_capacity(k);
    let mut q: Vec<Vec<f64>> = Vec::with_capacity(k + 1);

    // Seeded LCG, deterministic across runs
    let mut state = seed.wrapping_mul(2862933555777941757).wrapping_add(3037000493);
    let mut next = || -> f64 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let bits = (state >> 32) as u32;
        (bits as f64 / u32::MAX as f64) - 0.5
    };
    let mut q0: Vec<f64> = (0..n).map(|_| next()).collect();
    let nrm: f64 = q0.iter().map(|x| x * x).sum::<f64>().sqrt();
    if nrm < LANCZOS_TOL { return (alphas, betas, q); }
    for x in &mut q0 { *x /= nrm; }
    q.push(q0);

    for i in 0..k {
        let mut v = op(&q[i]);
        let alpha: f64 = (0..n).map(|p| q[i][p] * v[p]).sum();
        alphas.push(alpha);

        // r = v - α q[i] - β_{i-1} q[i-1]
        for p in 0..n { v[p] -= alpha * q[i][p]; }
        if i > 0 {
            let bp = betas[i - 1];
            for p in 0..n { v[p] -= bp * q[i - 1][p]; }
        }
        // Full re-orthogonalization (twice for numerical stability)
        for _ in 0..2 {
            for j in 0..=i {
                let dot: f64 = (0..n).map(|p| q[j][p] * v[p]).sum();
                for p in 0..n { v[p] -= dot * q[j][p]; }
            }
        }

        let beta: f64 = v.iter().map(|x| x * x).sum::<f64>().sqrt();
        if beta < LANCZOS_TOL || i == k - 1 { break; }
        for x in &mut v { *x /= beta; }
        q.push(v);
        betas.push(beta);
    }
    (alphas, betas, q)
}

/// Jacobi eigendecomposition for a small symmetric matrix.
/// Returns (eigenvalues, eigenvectors_columns) sorted ascending.
fn jacobi_eigen(mat: &mut [Vec<f64>]) -> (Vec<f64>, Vec<Vec<f64>>) {
    let n = mat.len();
    let mut v: Vec<Vec<f64>> = (0..n).map(|i| {
        let mut col = vec![0.0; n];
        col[i] = 1.0;
        col
    }).collect();

    for _ in 0..JACOBI_MAX_SWEEPS {
        // Sum of off-diagonal squared
        let mut off = 0.0_f64;
        for i in 0..n {
            for j in 0..n {
                if i != j { off += mat[i][j] * mat[i][j]; }
            }
        }
        off *= 0.5;
        if off < JACOBI_TOL { break; }

        for p in 0..n - 1 {
            for qx in p + 1..n {
                let apq = mat[p][qx];
                if apq.abs() < JACOBI_TOL { continue; }
                let app = mat[p][p];
                let aqq = mat[qx][qx];
                let theta = (aqq - app) / (2.0 * apq);
                let t = if theta.abs() > 1e15 {
                    1.0 / (2.0 * theta)
                } else {
                    let sign = if theta >= 0.0 { 1.0 } else { -1.0 };
                    sign / (theta.abs() + (theta * theta + 1.0).sqrt())
                };
                let c = 1.0 / (t * t + 1.0).sqrt();
                let s = t * c;

                mat[p][p] = app - t * apq;
                mat[qx][qx] = aqq + t * apq;
                mat[p][qx] = 0.0;
                mat[qx][p] = 0.0;

                for r in 0..n {
                    if r != p && r != qx {
                        let arp = mat[r][p];
                        let arq = mat[r][qx];
                        mat[r][p] = c * arp - s * arq;
                        mat[p][r] = mat[r][p];
                        mat[r][qx] = s * arp + c * arq;
                        mat[qx][r] = mat[r][qx];
                    }
                }
                for r in 0..n {
                    let vrp = v[r][p];
                    let vrq = v[r][qx];
                    v[r][p] = c * vrp - s * vrq;
                    v[r][qx] = s * vrp + c * vrq;
                }
            }
        }
    }

    let mut eigs: Vec<(f64, usize)> = (0..n).map(|i| (mat[i][i], i)).collect();
    eigs.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    let evals: Vec<f64> = eigs.iter().map(|(e, _)| *e).collect();
    let evecs: Vec<Vec<f64>> = eigs.iter().map(|(_, idx)| {
        (0..n).map(|r| v[r][*idx]).collect()
    }).collect();
    (evals, evecs)
}

/// Compute up to k smallest eigenpairs of L (or L_sym) via Lanczos.
/// Returns (sorted_eigenvalues, eigenvectors_in_original_basis).
fn smallest_eigenpairs<F: Fn(&[f64]) -> Vec<f64>>(
    n: usize,
    op: F,
    k: usize,
) -> (Vec<f64>, Vec<Vec<f64>>) {
    let kmax = LANCZOS_MAX_K.min(n);
    let (alphas, betas, q_basis) = lanczos(n, kmax, &op, 1);
    let m = alphas.len();
    if m == 0 { return (Vec::new(), Vec::new()); }

    // Build dense symmetric tridiagonal m×m
    let mut t = vec![vec![0.0; m]; m];
    for i in 0..m {
        t[i][i] = alphas[i];
        if i + 1 < m {
            let b = betas[i];
            t[i][i + 1] = b;
            t[i + 1][i] = b;
        }
    }
    let (ritz_vals, ritz_vecs) = jacobi_eigen(&mut t);

    // Reproject: x = Σ_j ritz_vecs[i][j] * q_basis[j]
    let want = k.min(m);
    let mut evals = Vec::with_capacity(want);
    let mut evecs: Vec<Vec<f64>> = Vec::with_capacity(want);
    for i in 0..want {
        evals.push(ritz_vals[i]);
        let mut x = vec![0.0; n];
        for (j, qj) in q_basis.iter().enumerate().take(m) {
            let coef = ritz_vecs[i][j];
            for p in 0..n { x[p] += coef * qj[p]; }
        }
        // Re-normalize (Lanczos basis isn't perfectly orthonormal in finite precision)
        let nrm: f64 = x.iter().map(|v| v * v).sum::<f64>().sqrt();
        if nrm > 0.0 { for v in &mut x { *v /= nrm; } }
        evecs.push(x);
    }
    (evals, evecs)
}

// ── fiedler ─────────────────────────────────────────────────────────

pub fn fiedler(graph: &Graph) -> String {
    let lap = match build_lap(graph) { Ok(l) => l, Err(e) => return e };
    if lap.n < 2 { return "Need ≥ 2 nodes for Fiedler analysis.".to_string(); }

    let (vals, vecs) = smallest_eigenpairs(lap.n, |x| mat_vec(&lap, x), 4);
    if vals.len() < 2 {
        return "Lanczos failed to converge ≥ 2 eigenpairs.".to_string();
    }
    // Skip eigenvalue closest to 0 (the constant nullspace vector)
    let mut idx_sorted: Vec<usize> = (0..vals.len()).collect();
    idx_sorted.sort_by(|&a, &b| vals[a].partial_cmp(&vals[b]).unwrap_or(std::cmp::Ordering::Equal));
    let lambda1 = vals[idx_sorted[0]];
    let lambda2 = vals[idx_sorted[1]];
    let v2 = &vecs[idx_sorted[1]];

    // Bisection by sign of v2 entries
    let mut pos: Vec<(String, f64)> = Vec::new();
    let mut neg: Vec<(String, f64)> = Vec::new();
    for (i, id) in lap.ids.iter().enumerate() {
        let val = v2[i];
        if val >= 0.0 { pos.push((id.clone(), val)); } else { neg.push((id.clone(), val)); }
    }
    pos.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    neg.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

    // Cut size: edges crossing the bisection
    let signs: Vec<bool> = (0..lap.n).map(|i| v2[i] >= 0.0).collect();
    let mut cut = 0usize;
    let mut total_edges = 0usize;
    for i in 0..lap.n {
        for &j in &lap.nbr[i] {
            if j > i {
                total_edges += 1;
                if signs[i] != signs[j] { cut += 1; }
            }
        }
    }

    let mut lines = vec![
        format!("=== Fiedler Spectral Bisection ({} nodes, {} edges) ===", lap.n, total_edges),
        format!("λ₁ (smallest)            = {:.6}  (should be ≈ 0)", lambda1),
        format!("λ₂ (algebraic conn.)    = {:.6}", lambda2),
        format!("Spectral gap λ₂ - λ₁    = {:.6}", lambda2 - lambda1),
        if lambda2 < 1e-6 {
            "  → graph appears DISCONNECTED (multiple components)".to_string()
        } else if lambda2 < 0.05 {
            "  → bottleneck/near-cut detected (low connectivity)".to_string()
        } else {
            "  → graph is well-connected".to_string()
        },
        String::new(),
        format!("Bisection: cut size = {}/{} edges ({:.1}%)", cut, total_edges,
            if total_edges > 0 { 100.0 * cut as f64 / total_edges as f64 } else { 0.0 }),
        format!("  Side A: {} nodes  |  Side B: {} nodes", pos.len(), neg.len()),
        String::new(),
    ];
    if !pos.is_empty() {
        lines.push(format!("Side A — top {} by Fiedler magnitude:", 8.min(pos.len())));
        for (id, v) in pos.iter().take(8) {
            lines.push(format!("  {:+.4}  {}", v, id));
        }
    }
    if !neg.is_empty() {
        lines.push(String::new());
        lines.push(format!("Side B — top {} by Fiedler magnitude:", 8.min(neg.len())));
        for (id, v) in neg.iter().take(8) {
            lines.push(format!("  {:+.4}  {}", v, id));
        }
    }
    lines.join("\n")
}

// ── spectral-cluster ────────────────────────────────────────────────

pub fn spectral_cluster(graph: &Graph, target: &str) -> String {
    let k: usize = if target.is_empty() {
        8
    } else {
        match target.parse::<usize>() {
            Ok(n) if (2..=30).contains(&n) => n,
            _ => return format!("Usage: codemap spectral-cluster [k=8, 2..30]  (got: {target:?})"),
        }
    };
    let lap = match build_lap(graph) { Ok(l) => l, Err(e) => return e };
    if lap.n < k {
        return format!("Need ≥ {} nodes for k={} clustering (have {}).", k, k, lap.n);
    }

    // Use normalized Laplacian for Shi-Malik clustering
    let (vals, vecs) = smallest_eigenpairs(lap.n, |x| mat_vec_norm(&lap, x), k + 2);
    if vecs.len() < k {
        return format!("Lanczos converged only {}/{} eigenpairs. Try smaller k.", vecs.len(), k);
    }

    // Build n × k embedding (skip the trivial first eigenvector if it's near zero)
    let skip_first = vals[0].abs() < 1e-6;
    let cols: Vec<&Vec<f64>> = if skip_first {
        vecs.iter().skip(1).take(k).collect()
    } else {
        vecs.iter().take(k).collect()
    };
    let kk = cols.len();
    let mut emb: Vec<Vec<f64>> = (0..lap.n).map(|i| {
        cols.iter().map(|c| c[i]).collect()
    }).collect();
    // Row-normalize (Ng-Jordan-Weiss 2002): each row → unit length
    for row in &mut emb {
        let nrm: f64 = row.iter().map(|x| x * x).sum::<f64>().sqrt();
        if nrm > 0.0 { for x in row.iter_mut() { *x /= nrm; } }
    }

    let labels = kmeans(&emb, k, kk);

    // Group + report
    let mut groups: HashMap<usize, Vec<&str>> = HashMap::new();
    for (i, lbl) in labels.iter().enumerate() {
        groups.entry(*lbl).or_default().push(lap.ids[i].as_str());
    }
    let mut sorted: Vec<(usize, Vec<&str>)> = groups.into_iter().collect();
    for (_, members) in sorted.iter_mut() { members.sort(); }
    sorted.sort_by_key(|(_, members)| std::cmp::Reverse(members.len()));

    let mut lines = vec![
        format!("=== Spectral Clustering ({} nodes, k={}) ===", lap.n, k),
        format!("Eigenvalues used: {:.4}, {:.4}, ...", vals.first().copied().unwrap_or(0.0), vals.get(1).copied().unwrap_or(0.0)),
        String::new(),
    ];
    for (i, (_, members)) in sorted.iter().enumerate() {
        let label = path_prefix_label(members.iter().copied());
        lines.push(format!("Cluster {} {}({} nodes):", i + 1, label, members.len()));
        for m in members.iter().take(8) {
            lines.push(format!("  {}", m));
        }
        if members.len() > 8 {
            lines.push(format!("  ... and {} more", members.len() - 8));
        }
        lines.push(String::new());
    }
    lines.join("\n")
}

fn path_prefix_label<'a, I: Iterator<Item = &'a str> + Clone>(members: I) -> String {
    let v: Vec<&str> = members.collect();
    if v.is_empty() { return String::new(); }
    let mut prefix = v[0];
    for s in &v[1..] {
        let cl = prefix.bytes().zip(s.bytes()).take_while(|(a, b)| a == b).count();
        prefix = &prefix[..cl];
    }
    if let Some(idx) = prefix.rfind('/') {
        format!("[{}/*] ", &prefix[..idx])
    } else if !prefix.is_empty() {
        format!("[{prefix}*] ")
    } else {
        String::new()
    }
}

// ── spectral-gap ────────────────────────────────────────────────────

pub fn spectral_gap(graph: &Graph) -> String {
    let lap = match build_lap(graph) { Ok(l) => l, Err(e) => return e };
    if lap.n < 4 { return "Need ≥ 4 nodes for spectral gap analysis.".to_string(); }

    let kmax = 25.min(lap.n);
    let (vals, _) = smallest_eigenpairs(lap.n, |x| mat_vec(&lap, x), kmax);
    if vals.len() < 3 {
        return "Lanczos failed to produce a useful spectrum.".to_string();
    }

    // Skip leading near-zero eigenvalues (count of components)
    let zero_count = vals.iter().take_while(|&&v| v < 1e-6).count();
    let components = zero_count.max(1);

    // Find the largest gap among the non-trivial eigenvalues; the
    // index where the gap is largest suggests the natural number of
    // communities (von Luxburg 2007, "A tutorial on spectral clustering").
    let mut best_gap = 0.0_f64;
    let mut best_k = 0usize;
    for i in zero_count..vals.len() - 1 {
        let g = vals[i + 1] - vals[i];
        if g > best_gap {
            best_gap = g;
            best_k = i + 1; // recommend k = i + 1 clusters
        }
    }

    let mut lines = vec![
        format!("=== Spectral Gap Analysis ({} nodes) ===", lap.n),
        format!("Connected components: {}", components),
        String::new(),
        "Eigenvalues (smallest first):".to_string(),
    ];
    for (i, v) in vals.iter().enumerate().take(20) {
        let marker = if i + 1 < vals.len() && i >= zero_count {
            let g = vals[i + 1] - vals[i];
            if (g - best_gap).abs() < 1e-12 { "  ← largest gap" } else { "" }
        } else { "" };
        lines.push(format!("  λ{:<2} = {:.6}{}", i + 1, v, marker));
    }
    lines.push(String::new());
    if best_k > 0 {
        lines.push(format!("Eigengap heuristic: graph naturally splits into ~{best_k} communities"));
        lines.push(format!("  (largest gap = {best_gap:.6} after dropping {zero_count} component eigenvector(s))"));
        lines.push(format!("  Try: codemap spectral-cluster {best_k}"));
    } else {
        lines.push("Eigengap heuristic: no clear community count (smooth spectrum)".to_string());
    }
    lines.join("\n")
}

// ── k-means (k-means++ init + Lloyd) ────────────────────────────────

fn kmeans(emb: &[Vec<f64>], k: usize, dim: usize) -> Vec<usize> {
    let n = emb.len();
    if n == 0 || k == 0 { return Vec::new(); }
    if n <= k {
        return (0..n).collect();
    }

    // k-means++ init (deterministic seed for reproducibility)
    let mut state: u64 = (n as u64).wrapping_mul(6364136223846793005).wrapping_add(0xC0DEC0DE);
    let mut next = || -> f64 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (state >> 32) as f64 / u32::MAX as f64
    };

    let mut centers: Vec<Vec<f64>> = Vec::with_capacity(k);
    centers.push(emb[(next() * n as f64) as usize % n].clone());
    let mut dists: Vec<f64> = emb.iter().map(|p| sqdist(p, &centers[0])).collect();
    while centers.len() < k {
        let total: f64 = dists.iter().sum();
        if total <= 0.0 {
            centers.push(emb[(next() * n as f64) as usize % n].clone());
        } else {
            let r = next() * total;
            let mut acc = 0.0;
            let mut chosen = 0usize;
            for (i, d) in dists.iter().enumerate() {
                acc += d;
                if acc >= r { chosen = i; break; }
            }
            centers.push(emb[chosen].clone());
        }
        for (i, p) in emb.iter().enumerate() {
            let d = sqdist(p, &centers[centers.len() - 1]);
            if d < dists[i] { dists[i] = d; }
        }
    }

    // Lloyd iterations
    let mut labels = vec![0usize; n];
    for _ in 0..50 {
        let mut changed = false;
        for (i, p) in emb.iter().enumerate() {
            let mut best = 0usize;
            let mut best_d = f64::INFINITY;
            for (c, ctr) in centers.iter().enumerate() {
                let d = sqdist(p, ctr);
                if d < best_d { best_d = d; best = c; }
            }
            if labels[i] != best { changed = true; labels[i] = best; }
        }
        if !changed { break; }
        let mut sums: Vec<Vec<f64>> = vec![vec![0.0; dim]; k];
        let mut counts = vec![0usize; k];
        for (i, p) in emb.iter().enumerate() {
            let lbl = labels[i];
            for d in 0..dim { sums[lbl][d] += p[d]; }
            counts[lbl] += 1;
        }
        for c in 0..k {
            if counts[c] > 0 {
                for d in 0..dim { centers[c][d] = sums[c][d] / counts[c] as f64; }
            }
        }
    }
    labels
}

fn sqdist(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(x, y)| (x - y).powi(2)).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-built two-clique graph: {0,1,2} fully connected, {3,4,5} fully
    /// connected, single bridge edge (2, 3). Fiedler bisection MUST split
    /// at the bridge — that's the textbook test.
    fn two_clique_lap() -> Lap {
        let ids: Vec<String> = (0..6).map(|i| format!("n{i}")).collect();
        let edges = [(0,1),(0,2),(1,2),(3,4),(3,5),(4,5),(2,3)];
        let mut nbr: Vec<Vec<usize>> = vec![Vec::new(); 6];
        for (a, b) in edges {
            nbr[a].push(b);
            nbr[b].push(a);
        }
        let deg: Vec<f64> = nbr.iter().map(|v| v.len() as f64).collect();
        Lap { n: 6, deg, nbr, ids }
    }

    #[test]
    fn lanczos_finds_zero_eigenvalue_of_connected_graph() {
        let lap = two_clique_lap();
        let (vals, _) = smallest_eigenpairs(lap.n, |x| mat_vec(&lap, x), 4);
        assert!(vals[0].abs() < 1e-6, "λ₁ should be 0, got {}", vals[0]);
        assert!(vals[1] > 0.01, "λ₂ should be positive, got {}", vals[1]);
    }

    #[test]
    fn fiedler_bisects_two_clique_at_bridge() {
        let lap = two_clique_lap();
        let (_, vecs) = smallest_eigenpairs(lap.n, |x| mat_vec(&lap, x), 4);
        let v2 = &vecs[1];
        // {0,1,2} should have one sign; {3,4,5} the other.
        let s012 = (v2[0].signum(), v2[1].signum(), v2[2].signum());
        let s345 = (v2[3].signum(), v2[4].signum(), v2[5].signum());
        assert_eq!(s012.0, s012.1);
        assert_eq!(s012.1, s012.2);
        assert_eq!(s345.0, s345.1);
        assert_eq!(s345.1, s345.2);
        assert_ne!(s012.0, s345.0, "the two cliques must end up on opposite sides");
    }

    #[test]
    fn jacobi_diagonalizes_symmetric_matrix() {
        // Known 3×3 symmetric matrix with eigenvalues {1, 2, 3}
        // diag(1,2,3) is the trivial case; let's rotate it.
        let mut a: Vec<Vec<f64>> = vec![
            vec![2.0, 1.0, 0.0],
            vec![1.0, 2.0, 1.0],
            vec![0.0, 1.0, 2.0],
        ];
        let (vals, _) = jacobi_eigen(&mut a);
        // Eigenvalues: 2-√2, 2, 2+√2
        let s = std::f64::consts::SQRT_2;
        assert!((vals[0] - (2.0 - s)).abs() < 1e-9);
        assert!((vals[1] - 2.0).abs() < 1e-9);
        assert!((vals[2] - (2.0 + s)).abs() < 1e-9);
    }
}
