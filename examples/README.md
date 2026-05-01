# codemap examples

Five end-to-end scenarios that show codemap in real use. Each one is a recipe — the commands you run, what they're for, and how the output composes into the next step.

If you're new and want to skip straight to "just do the right thing for me," start with [`codemap think`](#5-codemap-think---when-you-dont-know-what-to-run) at the bottom — it routes a plain-English goal through the right pipeline automatically.

---

## 1. Audit an unfamiliar codebase

You inherited a repo. You have 30 minutes before a planning meeting. You need to know: what's load-bearing, where the natural fault lines are, and what kind of risk is concentrated where.

```bash
codemap --dir ~/Desktop/some-project audit
```

What you get back:

- **Top chokepoints (betweenness centrality)** — files the entire dependency graph routes through. Touch one, ripple effects across half the repo.
- **Top brokers (structural-holes / Burt's constraint)** — files that connect otherwise-disconnected clusters. Often "glue" modules.
- **🚨 Dual-risk nodes** — both chokepoint AND broker. These are the load-bearing walls. Refactor with care.
- **Leiden cluster summary** — auto-named by path prefix (`[src/auth/*]`, `[src/billing/*]`). Tells you the natural module structure as the import graph sees it, not as the directory layout claims.
- **Per-EntityKind census** — counts of source files / endpoints / schema tables / etc. that the scan classified.

Follow-ups that compose:

```bash
# Drill into a specific load-bearing file
codemap --dir ~/Desktop/some-project callers src/auth/session.rs

# What breaks if I change it
codemap --dir ~/Desktop/some-project blast-radius src/auth/session.rs

# Recent activity heat
codemap --dir ~/Desktop/some-project hotspots
codemap --dir ~/Desktop/some-project churn HEAD~30
```

The whole audit + drill-down workflow takes ~5 seconds on a 2000-file repo.

---

## 2. Android APK analysis (DEX + native libs)

You're shipping a mobile app and want to verify: did I declare a permission I'm not actually using? Did I forget to declare one I AM using? What's in my native libs?

```bash
codemap --dir /tmp apk-info ./app-release.apk
```

What's registered in the graph:

- `AndroidPackage` node for the APK itself + every declared permission as a `Permission` node (apk → permission edge).
- **Every Java method** in every `classes*.dex` (multidex supported) → `BinaryFunction(binary_format=dex)` node with edge from the `AndroidPackage`. Capped at 5000 per APK.
- **Heuristic permission-usage edges** — methods calling `android.hardware.Camera`, `LocationManager`, `TelephonyManager`, etc. emit `BinaryFunction → Permission` edges. ~30 well-known protected APIs covered.
- Permissions discovered in code but **not** declared in the manifest auto-register with `discovered_via=dex`.

Now query:

```bash
# What code uses CAMERA?
codemap --dir /tmp meta-path "permission->method"

# Permissions used in code but not declared (or vice versa)
codemap --dir /tmp pagerank --type permission

# Most-central methods inside the app
codemap --dir /tmp pagerank --type bin_func
```

For the native side, extract each `lib/{abi}/*.so` and feed it to `bin-disasm`:

```bash
unzip ./app-release.apk lib/arm64-v8a/libapp.so -d /tmp
codemap --dir /tmp bin-disasm /tmp/lib/arm64-v8a/libapp.so
```

Each native function becomes a `BinaryFunction(binary_format=aarch64)` node. Function size from `STT_FUNC` (no instruction-count detail in v1, but enough to rank by size + grep by name).

---

## 3. Passive web recon (no live scraping)

You need to understand a website's tech stack and surface area without touching the live target. codemap is pure-static — you capture the artifacts, codemap parses them.

**Capture everything that matters first:**

```bash
mkdir -p /tmp/recon
curl -s -A 'Mozilla/5.0' -o /tmp/recon/index.html https://example.com/
curl -s -o /tmp/recon/robots.txt https://example.com/robots.txt
curl -s -o /tmp/recon/sitemap.xml https://example.com/sitemap.xml
curl -s 'https://crt.sh/?q=%25.example.com&output=json' -o /tmp/recon/crt.json
# JS-rendered sites: capture a HAR via Playwright/Burp/wget
playwright codegen https://example.com  # → save the trace as recon.har
```

**Then run the parsers:**

```bash
codemap --dir /tmp/recon web-dom            /tmp/recon/index.html
codemap --dir /tmp/recon web-fingerprint    /tmp/recon/index.html
codemap --dir /tmp/recon robots-parse       /tmp/recon/robots.txt
codemap --dir /tmp/recon web-sitemap-parse  /tmp/recon/sitemap.xml
codemap --dir /tmp/recon crt-parse          /tmp/recon/crt.json
```

Or shortcut the whole thing via `think`:

```bash
codemap --dir /tmp/recon think "recon /tmp/recon/index.html"
```

What ends up in the graph:

- `HttpEndpoint` per URL discovered (sitemap entries, robots paths, crt.sh subdomains, links in DOM).
- `Compiler` per detected framework (WordPress, Next.js, Spring Boot, etc. — ~50 signatures).
- `Cert` per issuer from crt.sh.
- Path-pattern auto-detection: a sitemap with 47K URLs of shape `/lawyer/{ID}` flags as ID-enumerable.
- Leaky-rule flags on robots: `Disallow: /admin/` shows up as a finding, not just a rule.

If you `codemap think "recon https://example.com"` with the live URL, codemap will **reject** the request and emit a copy-pasteable `curl + think` example. This is intentional: passive analysis is the design.

---

## 4. Diff two binary versions

You have v1 and v2 of an .exe and want to know what functions were added, removed, or kept. Useful for malware analysis, vendor update auditing, or your own release diffs.

```bash
codemap --dir /tmp binary-diff /tmp/app-v1.exe /tmp/app-v2.exe
```

Cross-graph promotion under `diff:{session}:` namespace:

- `pe:diff:{session}:a` — left binary (v1) with diff-summary attrs.
- `pe:diff:{session}:b` — right binary (v2) with diff-summary attrs.
- One `BinaryFunction` per unique imported symbol, with `diff_status` ∈ {`added`, `removed`, `unchanged`}. Unchanged functions receive edges from BOTH binaries.
- One `Dll` per imported library, same `diff_status` pattern.

Session ID is a stable hash of both file paths → re-running the same diff is idempotent (no ghost accumulation).

Now query:

```bash
# Just the new functions
codemap --dir /tmp pagerank --type bin_func    # ranked across both versions

# Filter to just this diff session
# (use the session ID from the binary-diff output header)
codemap --dir /tmp meta-path "pe->bin_func"
```

The diff is namespace-isolated, so it never pollutes a regular `audit` of the same repo.

---

## 5. `codemap think` — when you don't know what to run

163 actions is a lot. When the goal is fuzzy or you're staring at the catalog wondering which to pick, start here:

```bash
codemap --dir ~/some-project think "audit this codebase"
codemap --dir ~/some-project think "find load-bearing files"
codemap --dir ~/some-project think "security review"
codemap --dir ~/some-project think "hardcoded secrets"
codemap --dir /tmp think "reverse this windows binary /opt/sample/app.exe"
codemap --dir /tmp think "android apk /opt/apks/myapp.apk"
codemap --dir /tmp think "recon /tmp/captured.html"
codemap --dir /tmp think "compare /tmp/v1.exe /tmp/v2.exe"
codemap --dir /tmp think "ml model /tmp/llama-3.gguf"
```

What you get back:

```
=== codemap think (CodebaseAudit) ===

Goal:     audit this codebase
Intent:   codebase audit — one-page architectural risk overview
Target:   (scan dir — see --dir)
Pipeline: audit → summary

── audit ──
<full audit output>

── summary ──
<full insights summary output>

──
Pipeline above corresponds to: audit → summary
Next time skip `think` and run them directly if you want finer control.
```

Every invocation **shows you the chosen pipeline at the top** so you can run those actions directly next time. `think` is training wheels for the catalog, not a permanent dependency.

A few invariants worth knowing:

- **Live URLs are firmly rejected.** `codemap think "recon https://example.com"` returns a "capture the artifact first" message with a copy-pasteable `curl + think` invocation. codemap is pure-static; this guard means you (and any AI agent calling codemap on your behalf) don't accidentally trigger live scraping.
- **Path detection is automatic.** Any token in your goal that exists on disk becomes the pipeline's target. `codemap think "reverse /opt/sample/app.exe"` threads the path through `pe-meta`, `pe-imports`, `pe-strings`, `bin-disasm`, etc.
- **Fallback is a menu, not a guess.** If the goal doesn't match any intent, `think` lists the closest intents as suggestions. You see what your options are; codemap doesn't silently run the wrong thing.

---

## Where to next

- Full action catalog: [`README.md`](../README.md) (164 actions, grouped by category).
- Per-release design notes: [`EVOLUTION.log`](../EVOLUTION.log).
- Want to contribute a new action / EntityKind / format? [`CONTRIBUTING.md`](../CONTRIBUTING.md).
