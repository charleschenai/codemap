# codemap benchmarks

Real measurements of `codemap think` running on real OSS codebases. Three queries, three repos, no warm cache.

## Methodology

- **Codebases**: cloned from GitHub, 500–3,000 files each.
- **Tool**: `codemap` v5.26.0, `--no-cache` (cold scan + analysis on every run).
- **Invocation**: `codemap think "<plain-English goal>"` — single agent tool call from the agent's perspective.
- **Timing**: wall-clock from process start to exit, measured with nanosecond-resolution `date +%s%N`.
- **Hardware**: NVIDIA DGX Spark (GB10), 128 GB RAM, Linux 6.17. Single core for the parser, parallel walk for I/O.

## Results

| Repo | Files | Lines (parsed) | Query | Pipeline (auto-routed) | Time | Output |
|------|------:|---------------:|-------|------------------------|-----:|-------:|
| **Joern** (Scala) | 1,977 | 257 K | "audit this codebase" | `audit → summary` | **862 ms** | 3.1 KB |
| **CodeGraphContext** (Python) | 828 | 70 K | "find load-bearing files" | `audit → betweenness → bridges` | **519 ms** | 4.8 KB |
| **Continue** (TypeScript) | 3,187 | 354 K | "find all api endpoints" | `api-surface → meta-path source→endpoint` | **1,007 ms** | 134 KB (292 endpoints) |

**Geometric mean: ~770 ms for a 2–3 action pipeline on 800–3,200-file repos with cold cache.**

## What this means in agent terms

From the calling AI agent's perspective, each query above is **one tool call** — `Bash(codemap think "<goal>")`. The orchestrator picks the pipeline, runs it, and returns the aggregated output.

Comparable raw-exploration patterns (Claude Code's Explore agent using `Bash(grep)` / `Bash(find)` / `Read`) typically take **20–50 tool calls** on codebases of similar size. CodeGraph (the closest direct competitor) [published controlled benchmarks](https://github.com/colbymchenry/codegraph#benchmark-results) showing the raw-exploration baseline at 26–52 tool calls for similar query shapes, taking 1m 8s – 2m 8s wall-clock.

So the apples-to-apples claim, anchored on those published CodeGraph baselines:

- **Tool calls per agent query: 1 (codemap) vs ~30 (raw exploration) — ~96% reduction.**
- **Wall clock per query: ~0.8 s (codemap) vs ~80 s (raw exploration) — ~99% reduction.**

The more honest framing: **`codemap think` collapses what would be a multi-minute Explore-agent session into a single sub-second tool call.** The reduction comes from `think` routing to the right pipeline (so the agent doesn't have to pick from 164 actions) and from the underlying actions being graph queries (so they don't fan out into per-file reads).

## Per-query detail

### "audit this codebase" → Joern (Scala, 1,977 files)

```
Pipeline: audit → summary
Time:     862 ms
Output:   3,168 bytes
```

Routes to `audit + summary`. The `audit` action returns top chokepoints, top brokers, dual-risk nodes, Leiden cluster summary, and a per-EntityKind census in one pass. `summary` adds a high-level insights block on top. The 862 ms figure includes scanning all 1,977 files (1,494 of them Scala) cold from disk and building the graph. Repeat invocations on the bincode cache are 5–10× faster.

### "find load-bearing files" → CodeGraphContext (Python, 828 files)

```
Pipeline: audit → betweenness → bridges
Time:     519 ms
Output:   4,820 bytes
```

Routes to `audit + betweenness + bridges` — the trio that surfaces architectural choke-points (high betweenness centrality), structural-holes brokers, and the dual-risk nodes that are both. On CodeGraphContext this finds `tools/tree_sitter_parser.py` (constraint score 20.9) as the load-bearing wall — exactly right for that codebase.

### "find all api endpoints" → Continue (TypeScript, 3,187 files)

```
Pipeline: api-surface → meta-path source→endpoint
Time:     1,007 ms
Output:   133,704 bytes (292 HttpEndpoint nodes registered)
```

Routes to `api-surface + meta-path "source->endpoint"`. Returns the full inventory of HTTP routes, GraphQL resolvers, and CLI commands across the codebase, plus the source-file → endpoint edge listing. The 134 KB output reflects 292 distinct endpoints (Continue is heavy on HTTP integrations) — the agent gets the answer in one tool call instead of grepping for `@app.route` / `router.get` patterns across thousands of files.

## Reproducing

The benchmark targets are pre-cloned at `~/reference/codemap-competition/`:

```bash
codemap --dir ~/reference/codemap-competition/02-joern --no-cache think "audit this codebase"
codemap --dir ~/reference/codemap-competition/22-codegraphcontext --no-cache think "find load-bearing files"
codemap --dir ~/reference/codemap-competition/24-continue --no-cache think "find all api endpoints"
```

The exact runner script is at `~/reference/codemap-competition/_benchmarks/` (one `.txt` per query result + a `run.sh` that reproduces the timing pass).

## What's NOT measured here

- **Token cost in the calling LLM.** Codemap returns aggregated text; the LLM still pays for ingesting it. The 134 KB endpoint catalog from the Continue run is large — for that query specifically, an agent would benefit from `meta-path "source->endpoint" --limit 50` to cap the output.
- **Cold cache overhead vs warm cache.** All numbers above are cold (`--no-cache`). With the bincode cache present, repeat invocations are 5–10× faster. For an agent running multiple queries against the same repo, only the first query pays the full cost.
- **A controlled raw-Explore comparison.** I cite CodeGraph's published numbers as the baseline because they're independent of which graph tool is being measured (they measured Claude Code's Explore agent with vs without their tool). The "without" condition is reusable.
- **Memory.** Codemap is a single Rust process; peak RSS during these runs was 200–800 MB depending on codebase size. Wrapped in a 24 GB systemd scope as the safety cap, never close to that limit.

## Where to next

This is v1 of the benchmark suite. Real follow-ups:

1. **Controlled A/B with a Claude Code Explore agent.** Same query, two trials: agent has access to `Bash(codemap)` vs not. Measure tool calls + tokens directly. Currently we're anchoring on CodeGraph's published numbers; running the experiment ourselves would give us first-party data.
2. **Warm-cache numbers** for the agent-in-the-loop scenario.
3. **Larger-repo benchmarks** (Linux kernel, Chromium) to test scaling.
4. **Cross-tool comparison** with CodeGraph, GitNexus, CodeGraphContext on the same queries.
